from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from lowbit_lab.config import IMMUTABLE_REVISION_RE, SHA256_RE
from lowbit_lab.constants import (
    REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
    REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD,
    REFERENCE_ADDITIONAL_INCREMENTAL_CAP_USD,
    REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256,
    REFERENCE_ADDITIONAL_PRIOR_SPEND_USD,
    REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256,
    REFERENCE_AUTHORITY_SHA256,
    REFERENCE_BOOTSTRAP_AUTHORITY_SHA256,
    REFERENCE_CUMULATIVE_CAP_USD,
    REFERENCE_INCREMENTAL_CAP_USD,
    REFERENCE_RECOVERY_AUTHORITY_SHA256,
    REFERENCE_SETTLED_SMOKE_USD,
    REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256,
)
from lowbit_lab.handoff import sha256_json
from lowbit_lab.jsonio import emit
from lowbit_lab.reference_authority import (
    ADDITIONAL_AUTHORITY_PATH,
    AUTHORITY_PATH,
    BOOTSTRAP_AUTHORITY_PATH,
    RECOVERY_AUTHORITY_PATH,
    WORKSPACE_RECONCILIATION_AUTHORITY_PATH,
    ReferenceAuthorityError,
    validate_reference_additional_authority,
    validate_reference_authority,
    validate_reference_bootstrap_authority,
    validate_reference_recovery_authority,
    validate_workspace_scope_reconciliation_authority,
)
from lowbit_lab.reference_contract import (
    APPROVED_PROVIDER_AMENDMENT_PATH,
    APPROVED_PROVIDER_AMENDMENT_SHA256,
    APPROVED_TRUST_OVERRIDE_PLAN_PATH,
    APPROVED_TRUST_OVERRIDE_PLAN_SHA256,
    APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256,
    ORIGINAL_APPROVED_PLAN_PATH,
    ORIGINAL_APPROVED_PLAN_SHA256,
    REFERENCE_CONFIG_SCHEMA_VERSION,
    REFERENCE_GATE_FIELDS,
    REFERENCE_REPLACEMENT_AUDIT_REASON,
    REFERENCE_RESOURCES,
    reference_execution_scope_sha256,
)
from lowbit_lab.reference_provider_auth import OFFICIAL_MODAL_SERVER_URL
from lowbit_lab.reference_settlement import (
    AUTH_RECEIPT_MAXIMUM_AGE_SECONDS,
    ReferenceSettlementError,
    validate_workspace_auth_receipt,
    validate_workspace_zero_settlement_evidence,
)

SCHEMA_VERSION = 15
_V14_SCHEMA_SHA256 = {
    # Fresh, deployed, and supported legacy-migration v14 shapes.
    "afd74c9a39fd96ee08ab4f2564b714800def48a1e975bcfb9e3f08d80fd1c301",
    "d48ac282c25d5aba47b21131b8351f603b95f1636e081dbbd05de3da3a76e4aa",
    "73e0c9a1cafa2bd7bdcb79b5deff1b0f8366393c9edeb2d89303dfec7013bd8c",
    "00fafa630a6c02be11b9beff0dc65f5a321b0c50c76489520cb1758d364e9190",
    "16fa42b6dc7742c6bad40c62c0611681ee24952b62949d8917e9d72c03d0c993",
}
_V12_BUDGET_SCHEMA_SHA256 = {
    # Fresh schema-v12 creation and the deployed incremental-v12 migration shape.
    "fc16ab0b3adb0b84dbe85ac23afcc961ab64aed4e8ff64f5c852610ba555911b",
    "0ebfd58fb3a607cf764e25f120ee0c1476085c53097e4ee59b60e5ca0b7e2965",
}
_V13_RECOVERY_TABLE_SHA256 = {
    "reference_preidentity_settlements": {
        "0fdefe99f28960a37f018693d969faea429aefe6ba9b7efc651ec6a19559d2c9",
        "093e16096b0b7a5e2bf92c4c3ca7fe44789fee4109bfffdc86ed5c640e3d28c7",
    },
    "reference_replacement_entitlements": {
        "4bfdc09f9bc258a1d65879e154413a5140230ae21813f4041d26d2d412bf0af1",
        "1508470df20434b8b10a9a9f7028b675ae388076ea284163ded1427cb2399bca",
    },
}
REFERENCE_RESERVATION_USD = REFERENCE_INCREMENTAL_CAP_USD
TERMINAL_STATES = {"completed", "failed"}
TRANSITIONS = {
    "created": {"validated", "failed"},
    "validated": {"running", "failed"},
    "running": TERMINAL_STATES,
    "completed": set(),
    "failed": set(),
}

CONTROLLER_TERMINAL_STATES = {"paid_decision_required", "stopped", "failed"}
CONTROLLER_TRANSITIONS = {
    "created": {"validated", "failed"},
    "validated": {"preparing", "failed"},
    "preparing": CONTROLLER_TERMINAL_STATES,
    "paid_decision_required": set(),
    "stopped": set(),
    "failed": set(),
}

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS experiment_configs (
    experiment_id TEXT PRIMARY KEY,
    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS experiments (
    run_id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL REFERENCES experiment_configs(experiment_id) ON DELETE RESTRICT,
    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
    config_json TEXT NOT NULL,
    source_hashes_json TEXT NOT NULL,
    runtime_json TEXT NOT NULL,
    hardware_json TEXT NOT NULL,
    phase INTEGER NOT NULL CHECK(phase >= 0),
    mode TEXT NOT NULL CHECK(
        mode IN ('local_dry_run', 'modal_dry_run', 'local_activation', 'modal_reference')
    ),
    status TEXT NOT NULL CHECK(
        status IN ('created', 'validated', 'running', 'completed', 'failed')
    ),
    modal_cost_requested_usd TEXT NOT NULL DEFAULT '0',
    modal_cost_actual_usd TEXT DEFAULT '0',
    failure_reason TEXT,
    owner_id TEXT,
    lease_expires_at TEXT,
    heartbeat_at TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
    CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed'),
    CHECK((mode = 'modal_reference' AND status NOT IN ('completed', 'failed'))
          OR modal_cost_actual_usd IS NOT NULL),
    CHECK(mode = 'modal_reference' OR
          (modal_cost_requested_usd = '0' AND modal_cost_actual_usd = '0'))
);
CREATE INDEX IF NOT EXISTS experiments_config_sha ON experiments(config_sha256);
CREATE TABLE IF NOT EXISTS state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT,
    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS metrics (
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    value_json TEXT NOT NULL,
    unit TEXT,
    PRIMARY KEY (run_id, name)
);
CREATE TABLE IF NOT EXISTS artifacts (
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    kind TEXT NOT NULL,
    PRIMARY KEY (run_id, path)
);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    config_path TEXT NOT NULL,
    raw_config_sha256 TEXT,
    status TEXT NOT NULL CHECK(status IN ('received', 'linked', 'failed')),
    run_id TEXT REFERENCES experiments(run_id) ON DELETE RESTRICT,
    failure_reason TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    CHECK((status = 'received' AND ended_at IS NULL) OR
          (status IN ('linked', 'failed') AND ended_at IS NOT NULL)),
    CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
);
CREATE TABLE IF NOT EXISTS activation_gates (
    gate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
    gate_order INTEGER NOT NULL CHECK(gate_order >= 0),
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('created', 'running', 'completed', 'failed')),
    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
    authority_sha256 TEXT NOT NULL CHECK(length(authority_sha256) = 64),
    evidence_sha256 TEXT CHECK(evidence_sha256 IS NULL OR length(evidence_sha256) = 64),
    evidence_json TEXT,
    reused_gate_id TEXT REFERENCES activation_gates(gate_id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    failure_reason TEXT,
    evidence_valid INTEGER NOT NULL DEFAULT 1 CHECK(evidence_valid IN (0, 1)),
    invalidated_at TEXT,
    invalidation_reason TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    UNIQUE(run_id, gate_order),
    UNIQUE(run_id, name),
    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
    CHECK((status = 'completed' AND evidence_sha256 IS NOT NULL AND evidence_json IS NOT NULL)
          OR status != 'completed'),
    CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed'),
    CHECK((evidence_valid = 0 AND invalidated_at IS NOT NULL AND invalidation_reason IS NOT NULL)
          OR evidence_valid = 1)
);
CREATE INDEX IF NOT EXISTS activation_gates_reuse
ON activation_gates(name, input_sha256, authority_sha256, status, evidence_valid);
CREATE TABLE IF NOT EXISTS budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES experiments(run_id) ON DELETE RESTRICT,
    experiment_id TEXT NOT NULL,
    reference_execution_scope_sha256 TEXT
        CHECK(reference_execution_scope_sha256 IS NULL
              OR length(reference_execution_scope_sha256) = 64),
    trust_override_sha256 TEXT
        CHECK(trust_override_sha256 IS NULL OR length(trust_override_sha256) = 64),
    phase INTEGER NOT NULL CHECK(phase = 1),
    status TEXT NOT NULL CHECK(status IN (
        'reserved', 'submission_pending', 'submitted', 'settlement_pending', 'settled',
        'released', 'failed', 'audit_blocked'
    )),
    requested_cost_usd TEXT NOT NULL,
    provider_actual_cost_usd TEXT,
    provider_job_id TEXT UNIQUE,
    app_identity TEXT,
    provider_image_identity TEXT,
    billing_authority_sha256 TEXT,
    authoritative_report_identity_sha256 TEXT,
    billing_completeness_delay_seconds INTEGER,
    submitted_at TEXT,
    settlement_pending_at TEXT,
    settlement_mode TEXT CHECK(
        settlement_mode IS NULL OR settlement_mode = 'workspace_zero_preidentity'
    ),
    idempotency_key TEXT NOT NULL UNIQUE,
    settlement_identity TEXT UNIQUE,
    owner_id TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    failure_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK((status = 'settled' AND provider_actual_cost_usd IS NOT NULL
           AND settlement_identity IS NOT NULL) OR status != 'settled'),
    CHECK((settlement_mode IS NULL AND (
              (status IN ('submitted', 'settlement_pending', 'settled')
               AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
              OR status NOT IN ('submitted', 'settlement_pending', 'settled')
          )) OR (settlement_mode = 'workspace_zero_preidentity'
                 AND status = 'settled'
                 AND provider_job_id IS NULL AND app_identity IS NULL
                 AND provider_image_identity IS NULL AND submitted_at IS NULL
                 AND settlement_pending_at IS NULL
                 AND provider_actual_cost_usd = '0')),
    CHECK(reference_execution_scope_sha256 IS NULL
          OR (provider_job_id IS NULL AND submitted_at IS NULL)
          OR provider_image_identity IS NOT NULL),
    CHECK(reference_execution_scope_sha256 IS NULL OR
          (billing_authority_sha256 IS NOT NULL
           AND authoritative_report_identity_sha256 IS NOT NULL
           AND billing_completeness_delay_seconds > 0)),
    CHECK(reference_execution_scope_sha256 IS NULL
          OR status NOT IN ('submitted', 'settlement_pending', 'settled')
          OR settlement_mode = 'workspace_zero_preidentity'
          OR submitted_at IS NOT NULL),
    CHECK(reference_execution_scope_sha256 IS NULL
          OR status NOT IN ('settlement_pending', 'settled')
          OR settlement_mode = 'workspace_zero_preidentity'
          OR settlement_pending_at IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS budget_reservations_active_experiment
ON budget_reservations(experiment_id)
WHERE status IN (
    'reserved', 'submission_pending', 'submitted', 'settlement_pending', 'audit_blocked'
);
CREATE INDEX IF NOT EXISTS budget_reservations_reference_scope
ON budget_reservations(reference_execution_scope_sha256, status);
CREATE TRIGGER IF NOT EXISTS reference_provider_image_insert
BEFORE INSERT ON budget_reservations
WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
 AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
 AND NEW.provider_image_identity IS NULL
BEGIN
    SELECT RAISE(ABORT, 'reference provider image identity required');
END;
CREATE TRIGGER IF NOT EXISTS reference_provider_image_update
BEFORE UPDATE ON budget_reservations
WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
 AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
 AND NEW.provider_image_identity IS NULL
BEGIN
    SELECT RAISE(ABORT, 'reference provider image identity required');
END;
CREATE TABLE IF NOT EXISTS reference_approval_challenges (
    challenge_sha256 TEXT PRIMARY KEY CHECK(length(challenge_sha256) = 64),
    packet_sha256 TEXT NOT NULL CHECK(length(packet_sha256) = 64),
    approval_digest TEXT UNIQUE CHECK(approval_digest IS NULL OR length(approval_digest) = 64),
    expires_at TEXT,
    consumed_at TEXT,
    run_id TEXT REFERENCES experiments(run_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    CHECK((approval_digest IS NULL AND expires_at IS NULL AND consumed_at IS NULL)
          OR (approval_digest IS NOT NULL AND expires_at IS NOT NULL)),
    CHECK(consumed_at IS NULL OR run_id IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS provider_smoke_reservations (
    reservation_id TEXT PRIMARY KEY,
    action_contract_sha256 TEXT NOT NULL UNIQUE CHECK(length(action_contract_sha256) = 64),
    execution_scope_sha256 TEXT NOT NULL UNIQUE CHECK(length(execution_scope_sha256) = 64),
    challenge_sha256 TEXT NOT NULL UNIQUE CHECK(length(challenge_sha256) = 64),
    approval_digest TEXT NOT NULL UNIQUE CHECK(length(approval_digest) = 64),
    contract_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'reserved', 'submission_pending', 'submission_claimed', 'submitted',
        'settlement_pending', 'settled', 'failed', 'audit_blocked'
    )),
    requested_cost_usd TEXT NOT NULL CHECK(requested_cost_usd = '4.00'),
    owner_id TEXT NOT NULL,
    provider_call_id TEXT,
    observation_sha256 TEXT CHECK(observation_sha256 IS NULL OR length(observation_sha256) = 64),
    observation_json TEXT,
    settlement_pending_at TEXT,
    settlement_identity TEXT CHECK(settlement_identity IS NULL OR length(settlement_identity) = 64),
    provider_actual_cost_usd TEXT,
    failure_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK((status = 'submitted' AND provider_call_id IS NOT NULL) OR status != 'submitted'),
    CHECK((status IN ('failed', 'audit_blocked') AND failure_reason IS NOT NULL)
          OR status NOT IN ('failed', 'audit_blocked'))
);
CREATE TABLE IF NOT EXISTS reference_authority_slots (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    authority_sha256 TEXT NOT NULL CHECK(
        authority_sha256 = '8be94c8db6adae0de538ca41f43e7d250b9d4b5af4ffa6cd14ee445ca45d0d61'
    ),
    state TEXT NOT NULL CHECK(state = 'consumed'),
    execution_scope_sha256 TEXT NOT NULL UNIQUE CHECK(length(execution_scope_sha256) = 64),
    consumed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reference_workspace_scope_reconciliations (
    authority_sha256 TEXT PRIMARY KEY CHECK(length(authority_sha256) = 64),
    original_workspace_scope_sha256 TEXT NOT NULL UNIQUE
        CHECK(length(original_workspace_scope_sha256) = 64),
    authenticated_workspace_identity_sha256 TEXT NOT NULL UNIQUE
        CHECK(length(authenticated_workspace_identity_sha256) = 64),
    original_reservation_id TEXT NOT NULL UNIQUE
        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
    original_execution_scope_sha256 TEXT NOT NULL UNIQUE
        CHECK(length(original_execution_scope_sha256) = 64),
    billing_authority_sha256 TEXT NOT NULL CHECK(length(billing_authority_sha256) = 64),
    statement_sha256 TEXT NOT NULL CHECK(length(statement_sha256) = 64),
    approved_base_commit TEXT NOT NULL CHECK(length(approved_base_commit) = 40),
    replacement_action TEXT NOT NULL CHECK(replacement_action = 'u8_reference_replacement_once'),
    maximum_mapping_uses INTEGER NOT NULL CHECK(maximum_mapping_uses = 1),
    recorded_at TEXT NOT NULL,
    CHECK(original_workspace_scope_sha256 != authenticated_workspace_identity_sha256)
);
CREATE TABLE IF NOT EXISTS reference_preidentity_settlements (
    settlement_sha256 TEXT PRIMARY KEY CHECK(length(settlement_sha256) = 64),
    reservation_id TEXT NOT NULL UNIQUE
        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
    recovery_authority_sha256 TEXT NOT NULL
        CHECK(length(recovery_authority_sha256) = 64),
    original_workspace_scope_sha256 TEXT NOT NULL
        CHECK(length(original_workspace_scope_sha256) = 64),
    authenticated_workspace_identity_sha256 TEXT NOT NULL
        CHECK(length(authenticated_workspace_identity_sha256) = 64),
    workspace_reconciliation_authority_sha256 TEXT NOT NULL UNIQUE
        REFERENCES reference_workspace_scope_reconciliations(authority_sha256)
        ON DELETE RESTRICT,
    auth_binding_sha256 TEXT NOT NULL CHECK(length(auth_binding_sha256) = 64),
    pre_auth_receipt_sha256 TEXT NOT NULL CHECK(length(pre_auth_receipt_sha256) = 64),
    post_auth_receipt_sha256 TEXT NOT NULL CHECK(length(post_auth_receipt_sha256) = 64),
    billing_authority_sha256 TEXT NOT NULL CHECK(length(billing_authority_sha256) = 64),
    billing_method_sha256 TEXT NOT NULL CHECK(length(billing_method_sha256) = 64),
    authoritative_report_identity_sha256 TEXT NOT NULL
        CHECK(length(authoritative_report_identity_sha256) = 64),
    original_execution_scope_sha256 TEXT NOT NULL
        CHECK(length(original_execution_scope_sha256) = 64),
    failure_code TEXT NOT NULL CHECK(failure_code = 'auth_before_provider_identity'),
    query_start TEXT NOT NULL,
    query_end TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    completeness_delay_seconds INTEGER NOT NULL CHECK(completeness_delay_seconds > 0),
    actual_cost_usd TEXT NOT NULL CHECK(actual_cost_usd = '0'),
    report_sha256 TEXT NOT NULL UNIQUE CHECK(length(report_sha256) = 64),
    report_size_bytes INTEGER NOT NULL CHECK(report_size_bytes = 3),
    row_count INTEGER NOT NULL CHECK(row_count = 0),
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reference_replacement_entitlements (
    entitlement_sha256 TEXT PRIMARY KEY CHECK(length(entitlement_sha256) = 64),
    recovery_authority_sha256 TEXT NOT NULL
        CHECK(length(recovery_authority_sha256) = 64),
    workspace_reconciliation_authority_sha256 TEXT NOT NULL UNIQUE
        REFERENCES reference_workspace_scope_reconciliations(authority_sha256)
        ON DELETE RESTRICT,
    original_reservation_id TEXT NOT NULL UNIQUE
        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
    original_execution_scope_sha256 TEXT NOT NULL UNIQUE
        CHECK(length(original_execution_scope_sha256) = 64),
    settlement_sha256 TEXT NOT NULL UNIQUE
        REFERENCES reference_preidentity_settlements(settlement_sha256) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('available', 'consumed')),
    replacement_reservation_id TEXT UNIQUE
        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
    replacement_execution_scope_sha256 TEXT UNIQUE
        CHECK(replacement_execution_scope_sha256 IS NULL
              OR length(replacement_execution_scope_sha256) = 64),
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    consumed_auth_receipt_sha256 TEXT
        CHECK(consumed_auth_receipt_sha256 IS NULL OR length(consumed_auth_receipt_sha256) = 64),
    CHECK((state = 'available' AND replacement_reservation_id IS NULL
           AND replacement_execution_scope_sha256 IS NULL AND consumed_at IS NULL
           AND consumed_auth_receipt_sha256 IS NULL)
          OR (state = 'consumed' AND replacement_reservation_id IS NOT NULL
              AND replacement_execution_scope_sha256 IS NOT NULL AND consumed_at IS NOT NULL
              AND consumed_auth_receipt_sha256 IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS reference_additional_grants (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    authority_sha256 TEXT NOT NULL UNIQUE CHECK(length(authority_sha256) = 64),
    prior_settlement_receipt_sha256 TEXT NOT NULL UNIQUE
        CHECK(length(prior_settlement_receipt_sha256) = 64),
    prior_execution_scope_sha256 TEXT NOT NULL
        CHECK(length(prior_execution_scope_sha256) = 64),
    prior_actual_cost_usd TEXT NOT NULL CHECK(prior_actual_cost_usd = '0.00564445'),
    incremental_cap_usd TEXT NOT NULL CHECK(incremental_cap_usd = '4.00'),
    cumulative_cap_usd TEXT NOT NULL CHECK(cumulative_cap_usd = '4.00564445'),
    state TEXT NOT NULL CHECK(state IN ('available', 'consumed')),
    active_reservation_id TEXT UNIQUE
        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
    active_execution_scope_sha256 TEXT
        CHECK(active_execution_scope_sha256 IS NULL
              OR length(active_execution_scope_sha256) = 64),
    reserved_at TEXT,
    consumed_at TEXT,
    consumed_auth_receipt_sha256 TEXT
        CHECK(consumed_auth_receipt_sha256 IS NULL
              OR length(consumed_auth_receipt_sha256) = 64),
    created_at TEXT NOT NULL,
    CHECK((state = 'available' AND consumed_at IS NULL
           AND consumed_auth_receipt_sha256 IS NULL)
          OR (state = 'consumed' AND active_reservation_id IS NOT NULL
              AND active_execution_scope_sha256 IS NOT NULL
              AND reserved_at IS NOT NULL AND consumed_at IS NOT NULL
              AND consumed_auth_receipt_sha256 IS NOT NULL)),
    CHECK((active_reservation_id IS NULL AND active_execution_scope_sha256 IS NULL
           AND reserved_at IS NULL)
          OR (active_reservation_id IS NOT NULL
              AND active_execution_scope_sha256 IS NOT NULL AND reserved_at IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS controller_cycles (
    cycle_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    context_sha256 TEXT NOT NULL CHECK(length(context_sha256) = 64),
    authority_sha256 TEXT NOT NULL CHECK(length(authority_sha256) = 64),
    selected_action TEXT NOT NULL CHECK(selected_action = 'prepare'),
    state TEXT NOT NULL CHECK(state IN (
        'created', 'validated', 'preparing', 'paid_decision_required', 'stopped', 'failed'
    )),
    owner_id TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    stop_reason TEXT,
    artifact_path TEXT,
    artifact_sha256 TEXT CHECK(artifact_sha256 IS NULL OR length(artifact_sha256) = 64),
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ended_at TEXT,
    UNIQUE(workspace_id, generation),
    CHECK((state IN ('paid_decision_required', 'stopped', 'failed') AND ended_at IS NOT NULL)
          OR (state NOT IN ('paid_decision_required', 'stopped', 'failed') AND ended_at IS NULL)),
    CHECK((artifact_path IS NULL) = (artifact_sha256 IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS controller_cycles_active_workspace
ON controller_cycles(workspace_id)
WHERE state IN ('created', 'validated', 'preparing');
CREATE TABLE IF NOT EXISTS controller_cycle_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id TEXT NOT NULL REFERENCES controller_cycles(cycle_id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK(generation > 0),
    from_state TEXT,
    to_state TEXT NOT NULL CHECK(to_state IN (
        'created', 'validated', 'preparing', 'paid_decision_required', 'stopped', 'failed'
    )),
    reason TEXT,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS controller_cycle_transitions_cycle
ON controller_cycle_transitions(cycle_id, id);
"""

EVIDENCE_TABLES = (
    "experiment_configs",
    "experiments",
    "state_transitions",
    "metrics",
    "artifacts",
    "attempts",
)

V2_REPLACEMENT_SCHEMA = (
    """CREATE TABLE experiment_configs_v2 (
        experiment_id TEXT PRIMARY KEY,
        config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
        config_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )""",
    """CREATE TABLE experiments_v2 (
        run_id TEXT PRIMARY KEY,
        experiment_id TEXT NOT NULL
            REFERENCES experiment_configs_v2(experiment_id) ON DELETE RESTRICT,
        config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
        config_json TEXT NOT NULL,
        source_hashes_json TEXT NOT NULL,
        runtime_json TEXT NOT NULL,
        hardware_json TEXT NOT NULL,
        phase INTEGER NOT NULL CHECK(phase >= 0),
        mode TEXT NOT NULL CHECK(
            mode IN ('local_dry_run', 'modal_dry_run', 'local_activation')
        ),
        status TEXT NOT NULL CHECK(
            status IN ('created', 'validated', 'running', 'completed', 'failed')
        ),
        modal_cost_requested_usd TEXT NOT NULL DEFAULT '0',
        modal_cost_actual_usd TEXT NOT NULL DEFAULT '0',
        failure_reason TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
              (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
        CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
    )""",
    """CREATE TABLE state_transitions_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        from_state TEXT,
        to_state TEXT NOT NULL,
        reason TEXT,
        occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )""",
    """CREATE TABLE metrics_v2 (
        run_id TEXT NOT NULL REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        name TEXT NOT NULL,
        value_json TEXT NOT NULL,
        unit TEXT,
        PRIMARY KEY (run_id, name)
    )""",
    """CREATE TABLE artifacts_v2 (
        run_id TEXT NOT NULL REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        path TEXT NOT NULL,
        sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
        size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
        kind TEXT NOT NULL,
        PRIMARY KEY (run_id, path)
    )""",
    """CREATE TABLE attempts_v2 (
        attempt_id TEXT PRIMARY KEY,
        config_path TEXT NOT NULL,
        raw_config_sha256 TEXT,
        status TEXT NOT NULL CHECK(status IN ('received', 'linked', 'failed')),
        run_id TEXT REFERENCES experiments_v2(run_id) ON DELETE RESTRICT,
        failure_reason TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        CHECK((status = 'received' AND ended_at IS NULL) OR
              (status IN ('linked', 'failed') AND ended_at IS NOT NULL)),
        CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
    )""",
)

V2_COPY_COLUMNS = {
    "experiment_configs": "experiment_id, config_sha256, config_json, created_at",
    "experiments": (
        "run_id, experiment_id, config_sha256, config_json, source_hashes_json, "
        "runtime_json, hardware_json, phase, mode, status, modal_cost_requested_usd, "
        "modal_cost_actual_usd, failure_reason, started_at, ended_at"
    ),
    "state_transitions": "id, run_id, from_state, to_state, reason, occurred_at",
    "metrics": "run_id, name, value_json, unit",
    "artifacts": "run_id, path, sha256, size_bytes, kind",
    "attempts": (
        "attempt_id, config_path, raw_config_sha256, status, run_id, failure_reason, "
        "started_at, ended_at"
    ),
}


class DatabaseError(RuntimeError):
    pass


def _database_money(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except (InvalidOperation, TypeError) as exc:
        raise DatabaseError(f"{label} must be a decimal string") from exc
    if (
        not isinstance(value, str)
        or not parsed.is_finite()
        or parsed < 0
        or parsed.as_tuple().exponent < -6
    ):
        raise DatabaseError(f"{label} must be finite, non-negative, and at most 6 decimals")
    return parsed


def _database_actual_money(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except (InvalidOperation, TypeError) as exc:
        raise DatabaseError(f"{label} must be a decimal string") from exc
    if (
        not isinstance(value, str)
        or not parsed.is_finite()
        or parsed < 0
        or parsed.as_tuple().exponent < -10
    ):
        raise DatabaseError(f"{label} must be finite, non-negative, and at most 10 decimals")
    return parsed


def _database_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DatabaseError(f"{label} must be lowercase SHA-256")
    return value


def _database_timestamp(value: str, label: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise DatabaseError(f"{label} must be an ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise DatabaseError(f"{label} must be timezone-aware")
    return timestamp


def _validate_additional_provider_auth_receipt(
    content: bytes,
    *,
    reservation_id: str,
    execution_scope_sha256: str,
    authority_sha256: str,
) -> str:
    """Validate the sanitized receipt bound to the final provider boundary."""
    try:
        raw = json.loads(content)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatabaseError("reference additional auth receipt is invalid") from exc
    expected_fields = {
        "additional_authority_sha256",
        "authenticated_workspace_identity_sha256",
        "environment_overrides_present",
        "kind",
        "provider_environment",
        "reference_execution_scope_sha256",
        "reservation_id",
        "schema_version",
        "sdk_version",
        "server_url",
    }
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if (
        not isinstance(raw, dict)
        or set(raw) != expected_fields
        or content != canonical
        or raw["kind"] != "reference_additional_provider_auth_receipt"
        or raw["schema_version"] != 1
        or raw["additional_authority_sha256"] != authority_sha256
        or raw["reservation_id"] != reservation_id
        or raw["reference_execution_scope_sha256"] != execution_scope_sha256
        or raw["server_url"] != OFFICIAL_MODAL_SERVER_URL
        or raw["environment_overrides_present"] is not False
        or not isinstance(raw["provider_environment"], str)
        or not raw["provider_environment"]
        or not isinstance(raw["sdk_version"], str)
        or not raw["sdk_version"]
        or not isinstance(raw["authenticated_workspace_identity_sha256"], str)
        or SHA256_RE.fullmatch(raw["authenticated_workspace_identity_sha256"]) is None
    ):
        raise DatabaseError("reference additional auth receipt is invalid")
    return hashlib.sha256(content).hexdigest()


def _reference_boundary_consumed(
    connection: sqlite3.Connection,
    *,
    reservation_id: str,
    execution_scope_sha256: str,
) -> bool:
    """Require one exact reservation-specific authority generation after the boundary."""
    original = connection.execute(
        """SELECT 1 FROM reference_authority_slots
        WHERE singleton = 1 AND state = 'consumed' AND execution_scope_sha256 = ?""",
        (execution_scope_sha256,),
    ).fetchone()
    replacement = connection.execute(
        """SELECT state, replacement_execution_scope_sha256
        FROM reference_replacement_entitlements
        WHERE replacement_reservation_id = ?""",
        (reservation_id,),
    ).fetchone()
    additional = connection.execute(
        """SELECT state, active_execution_scope_sha256, consumed_auth_receipt_sha256
        FROM reference_additional_grants
        WHERE singleton = 1 AND active_reservation_id = ?""",
        (reservation_id,),
    ).fetchone()
    if replacement is not None:
        return (
            additional is None
            and replacement["state"] == "consumed"
            and replacement["replacement_execution_scope_sha256"] == execution_scope_sha256
        )
    if additional is not None:
        return (
            additional["state"] == "consumed"
            and additional["active_execution_scope_sha256"] == execution_scope_sha256
            and additional["consumed_auth_receipt_sha256"] is not None
        )
    return original is not None


def _committed_provider_cost(connection: sqlite3.Connection) -> Decimal:
    committed = Decimal("0")
    for row in connection.execute(
        """SELECT status, requested_cost_usd, provider_actual_cost_usd,
            reference_execution_scope_sha256
        FROM budget_reservations WHERE status != 'released'"""
    ):
        use_actual = (
            row["reference_execution_scope_sha256"] is not None
            and row["status"] in {"settled", "failed"}
            and row["provider_actual_cost_usd"] is not None
        )
        value = row["provider_actual_cost_usd"] if use_actual else row["requested_cost_usd"]
        parser = _database_actual_money if use_actual else _database_money
        committed += parser(value, "stored reference reservation cost")
    committed += _committed_provider_smoke_cost(connection)
    return committed


def _committed_reference_cost(connection: sqlite3.Connection) -> Decimal:
    committed = Decimal("0")
    for row in connection.execute(
        """SELECT status, requested_cost_usd, provider_actual_cost_usd
        FROM budget_reservations WHERE status != 'released'"""
    ):
        use_actual = (
            row["status"] in {"settled", "failed"} and row["provider_actual_cost_usd"] is not None
        )
        value = row["provider_actual_cost_usd"] if use_actual else row["requested_cost_usd"]
        parser = _database_actual_money if use_actual else _database_money
        committed += parser(value, "stored reference reservation cost")
    return committed


def _committed_provider_smoke_cost(connection: sqlite3.Connection) -> Decimal:
    committed = Decimal("0")
    for row in connection.execute(
        """SELECT status, requested_cost_usd, provider_actual_cost_usd
        FROM provider_smoke_reservations"""
    ):
        use_actual = (
            row["status"] in {"settled", "failed"} and row["provider_actual_cost_usd"] is not None
        )
        value = row["provider_actual_cost_usd"] if use_actual else row["requested_cost_usd"]
        parser = _database_actual_money if use_actual else _database_money
        committed += parser(value, "stored provider smoke cost")
    return committed


def _validate_reference_additional_prior_lineage(connection: sqlite3.Connection) -> None:
    prior = connection.execute(
        """SELECT status, provider_actual_cost_usd
        FROM budget_reservations
        WHERE settlement_identity = ? AND reference_execution_scope_sha256 = ?""",
        (
            REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256,
            REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256,
        ),
    ).fetchone()
    if (
        prior is None
        or prior["status"] not in {"settled", "failed"}
        or _database_actual_money(prior["provider_actual_cost_usd"], "additional prior actual cost")
        != REFERENCE_ADDITIONAL_PRIOR_SPEND_USD - REFERENCE_SETTLED_SMOKE_USD
        or _committed_provider_cost(connection) != REFERENCE_ADDITIONAL_PRIOR_SPEND_USD
    ):
        raise DatabaseError(
            "reference additional prior receipt, scope, or actual-cost lineage has drifted"
        )


def _reference_billing_report(
    report_json: str, report_sha256: str
) -> tuple[dict[str, object], Decimal]:
    _database_sha256(report_sha256, "billing_report_sha256")
    try:
        report = json.loads(report_json)
    except json.JSONDecodeError as exc:
        raise DatabaseError("billing report receipt must be canonical JSON") from exc
    fields = {
        "schema_version",
        "kind",
        "provider_job_id",
        "billing_authority_sha256",
        "authoritative_report_identity_sha256",
        "covered_through",
        "actual_cost_usd",
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if (
        not isinstance(report, dict)
        or set(report) != fields
        or canonical != report_json
        or hashlib.sha256(canonical.encode()).hexdigest() != report_sha256
        or report.get("schema_version") != 1
        or report.get("kind") != "provider_billing_report_receipt"
        or not isinstance(report.get("provider_job_id"), str)
        or not report["provider_job_id"]
    ):
        raise DatabaseError("billing report receipt identity is invalid")
    for field in ("billing_authority_sha256", "authoritative_report_identity_sha256"):
        if not isinstance(report[field], str) or SHA256_RE.fullmatch(report[field]) is None:
            raise DatabaseError("billing report receipt authority is invalid")
    if not isinstance(report.get("covered_through"), str):
        raise DatabaseError("billing report receipt coverage is invalid")
    _database_timestamp(report["covered_through"], "covered_through")
    if not isinstance(report.get("actual_cost_usd"), str):
        raise DatabaseError("billing report receipt cost is invalid")
    return report, _database_actual_money(report["actual_cost_usd"], "actual_cost_usd")


def _reference_challenge(config_json: str, config_sha256: str) -> tuple[str, dict[str, Any]]:
    try:
        raw = json.loads(config_json)
    except json.JSONDecodeError as exc:
        raise DatabaseError("reference config must be canonical JSON") from exc
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if canonical != config_json or hashlib.sha256(canonical.encode()).hexdigest() != config_sha256:
        raise DatabaseError("reference config identity mismatch")
    top_fields = {
        "schema_version",
        "kind",
        "experiment_id",
        "original_approved_plan_path",
        "original_approved_plan_sha256",
        "approved_amendment_path",
        "approved_amendment_sha256",
        "approved_trust_override_plan_path",
        "approved_trust_override_plan_sha256",
        "budget_policy_path",
        "inputs",
        "authority_files",
        "resources",
        "provider",
        "gates",
        "approval_artifact_path",
    }
    input_fields = {
        "source_revision",
        "weight_inventory_sha256",
        "weight_inventory_tensor_bytes",
        "provenance_manifest_sha256",
        "runtime_receipt_sha256",
        "evaluation_lock_sha256",
        "evaluation_max_context_tokens",
        "formula_authority_sha256",
        "reviewed_commit_sha256",
        "control_plane_sha256",
    }
    authority_fields = {
        "weight_inventory_path",
        "source_shard_metadata_path",
        "provenance_manifest_path",
        "runtime_lock_path",
        "runtime_receipt_path",
        "evaluation_lock_path",
        "evaluation_fixture_root",
    }
    provider_fields = {
        "submit",
        "scheduling_enabled",
        "cloud_upload",
        "mounts",
        "volumes",
        "secrets",
        "credentials_source",
        "workspace_scope_sha256",
        "environment_scope_sha256",
        "constraint_contract_path",
        "constraint_contract_sha256",
        "observation_receipt_path",
        "observation_receipt_sha256",
        "observation_screenshot_sha256",
        "trust_override_path",
        "trust_override_sha256",
        "human_approval_statement_sha256",
        "billing_authority_path",
        "billing_authority_sha256",
        "authoritative_report_identity_sha256",
        "billing_completeness_delay_seconds",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) != top_fields
        or raw.get("schema_version") != REFERENCE_CONFIG_SCHEMA_VERSION
        or raw.get("kind") != "modal_reference_preview"
        or not isinstance(raw.get("inputs"), dict)
        or set(raw["inputs"]) != input_fields
        or raw.get("resources") != REFERENCE_RESOURCES
        or not isinstance(raw.get("authority_files"), dict)
        or set(raw["authority_files"]) != authority_fields
        or not isinstance(raw.get("provider"), dict)
        or set(raw["provider"]) != provider_fields
        or not isinstance(raw.get("gates"), dict)
        or set(raw["gates"]) != REFERENCE_GATE_FIELDS
    ):
        raise DatabaseError("reference config schema is invalid")
    provider = raw["provider"]
    if (
        provider["submit"] is not False
        or provider["scheduling_enabled"] is not False
        or provider["cloud_upload"] is not False
        or provider["mounts"] != []
        or provider["volumes"] != []
        or provider["secrets"] != []
        or provider["credentials_source"] != "provider_local"
    ):
        raise DatabaseError("reference provider boundary is invalid")
    if (
        raw["original_approved_plan_path"] != ORIGINAL_APPROVED_PLAN_PATH
        or raw["original_approved_plan_sha256"] != ORIGINAL_APPROVED_PLAN_SHA256
        or raw["approved_amendment_path"] != APPROVED_PROVIDER_AMENDMENT_PATH
        or raw["approved_amendment_sha256"] != APPROVED_PROVIDER_AMENDMENT_SHA256
        or raw["approved_trust_override_plan_path"] != APPROVED_TRUST_OVERRIDE_PLAN_PATH
        or raw["approved_trust_override_plan_sha256"] != APPROVED_TRUST_OVERRIDE_PLAN_SHA256
        or not str(raw["budget_policy_path"]).startswith("configs/local/")
        or (
            raw["approval_artifact_path"] is not None
            and not str(raw["approval_artifact_path"]).startswith("configs/local/")
        )
    ):
        raise DatabaseError("reference authority paths or hashes are invalid")
    for digest_name in ("workspace_scope_sha256", "environment_scope_sha256"):
        if (
            not isinstance(provider[digest_name], str)
            or SHA256_RE.fullmatch(provider[digest_name]) is None
        ):
            raise DatabaseError("reference provider authority is invalid")
    for digest_name in (
        "observation_screenshot_sha256",
        "trust_override_sha256",
        "human_approval_statement_sha256",
    ):
        if (
            not isinstance(provider[digest_name], str)
            or SHA256_RE.fullmatch(provider[digest_name]) is None
        ):
            raise DatabaseError("reference provider trust override is invalid")
    if provider["human_approval_statement_sha256"] != APPROVED_TRUST_OVERRIDE_STATEMENT_SHA256:
        raise DatabaseError("reference provider human approval statement is invalid")
    if (
        not isinstance(provider["authoritative_report_identity_sha256"], str)
        or SHA256_RE.fullmatch(provider["authoritative_report_identity_sha256"]) is None
        or not isinstance(provider["billing_completeness_delay_seconds"], int)
        or isinstance(provider["billing_completeness_delay_seconds"], bool)
        or provider["billing_completeness_delay_seconds"] <= 0
    ):
        raise DatabaseError("reference provider billing authority is invalid")
    inputs = raw["inputs"]
    if (
        not isinstance(inputs["source_revision"], str)
        or IMMUTABLE_REVISION_RE.fullmatch(inputs["source_revision"]) is None
    ):
        raise DatabaseError("reference source_revision is not an immutable revision")
    for digest_name in (
        "weight_inventory_sha256",
        "evaluation_lock_sha256",
        "formula_authority_sha256",
    ):
        if (
            not isinstance(inputs[digest_name], str)
            or SHA256_RE.fullmatch(inputs[digest_name]) is None
        ):
            raise DatabaseError("reference execution scope authority is incomplete")
    for path_name, digest_name in (
        ("constraint_contract_path", "constraint_contract_sha256"),
        ("observation_receipt_path", "observation_receipt_sha256"),
        ("billing_authority_path", "billing_authority_sha256"),
        ("trust_override_path", "trust_override_sha256"),
    ):
        authority_path = provider[path_name]
        if (
            not isinstance(authority_path, str)
            or Path(authority_path).is_absolute()
            or ".." in Path(authority_path).parts
            or not Path(authority_path).as_posix().startswith("reports/local/")
            or not isinstance(provider[digest_name], str)
            or SHA256_RE.fullmatch(provider[digest_name]) is None
        ):
            raise DatabaseError("reference provider authority is invalid")
    challenge_material = {
        key: value for key, value in raw.items() if key != "approval_artifact_path"
    }
    challenge_json = json.dumps(
        challenge_material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(challenge_json.encode()).hexdigest(), raw


def _database_private_data_scan(value: object, *, path: str = "reference") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if key not in {"credentials_source", "secrets"} and any(
                marker in lowered
                for marker in ("password", "passwd", "credential", "secret", "api_key")
            ):
                raise DatabaseError(f"private or credential-shaped field is forbidden: {path}")
            _database_private_data_scan(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _database_private_data_scan(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and (
        re.search(r"(?i)(?:^|\s)[A-Z]:[\\/]", value)
        or re.search(r"(?i)/(?:mnt/[a-z]/Users|home)/[^/\s]+/", value)
        or re.search(r"\bAKIA[0-9A-Z]{16}\b", value)
        or re.search(r"\bgh[opsu]_[A-Za-z0-9]{20,}\b", value)
        or re.search(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}", value)
        or re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", value)
    ):
        raise DatabaseError(f"private machine path is forbidden: {path}")


def _controller_identifier(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None
    ):
        raise DatabaseError(f"{label} must be a bounded portable identifier")
    _database_private_data_scan(value, path=label)
    return value


def _controller_text(value: str, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DatabaseError(f"{label} must be non-empty and at most {maximum} characters")
    _database_private_data_scan(value, path=label)
    return value


def _controller_artifact_path(value: str) -> str:
    value = _controller_text(value, "artifact_path", maximum=512)
    path = Path(value)
    portable = path.as_posix()
    if (
        path.is_absolute()
        or "\\" in value
        or ".." in path.parts
        or portable != value
        or not portable.startswith(("reports/local/", "artifacts/local/"))
    ):
        raise DatabaseError("artifact_path must be a portable local-artifact path")
    return value


def _validate_activation_run_config(config_json: str, requested_cost: str) -> None:
    try:
        config = json.loads(config_json)
        requested = Decimal(requested_cost)
        configured_requested = Decimal(config["modal"]["requested_cost_usd"])
    except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
        raise DatabaseError("local_activation run requires complete canonical config") from exc
    if not requested.is_finite() or requested != 0 or configured_requested != 0:
        raise DatabaseError("local_activation run cost must remain zero")
    target = config.get("target")
    activation = config.get("activation")
    if (
        config.get("mode") != "local_activation"
        or config.get("weights_required") is not False
        or not isinstance(target, dict)
        or target.get("status") != "configured"
        or not isinstance(target.get("identifier"), str)
        or not target["identifier"].strip()
        or not isinstance(target.get("revision"), str)
        or IMMUTABLE_REVISION_RE.fullmatch(target["revision"]) is None
        or not isinstance(target.get("license"), str)
        or not target["license"].strip()
        or not isinstance(activation, dict)
        or activation.get("preview_only") is not False
        or activation.get("scheduling_enabled") is not False
        or activation.get("destructive_cleanup_enabled") is not False
        or config.get("privacy", {}).get("allow_cloud_upload") is not False
        or config["modal"].get("submit") is not False
        or config["modal"].get("gpu_type") != "none"
        or config["modal"].get("gpu_count") != 0
        or config["modal"].get("cleanup") != "retain"
    ):
        raise DatabaseError("local_activation config is not executable")
    for name in (
        "approved_plan_sha256",
        "runtime_decision_sha256",
        "runtime_lock_sha256",
        "metadata_policy_sha256",
        "evaluation_lock_sha256",
    ):
        value = activation.get(name)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise DatabaseError("local_activation config authority hashes are incomplete")


def confine_results_db(root: Path, path: Path) -> Path:
    root = root.resolve()
    results_root = (root / "results").resolve()
    if not results_root.is_relative_to(root):
        raise DatabaseError("results directory resolves outside repository")
    candidate = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if not candidate.is_relative_to(results_root):
        raise DatabaseError("database path must resolve under repository results/")
    return candidate


def _budget_schema_sha256(connection: sqlite3.Connection) -> str:
    """Fingerprint the exact decision-bearing v12 table, indexes, and triggers."""
    table_info = [
        tuple(row) for row in connection.execute("PRAGMA table_info(budget_reservations)")
    ]
    objects = [
        (row[0], row[1], " ".join(str(row[2]).split()))
        for row in connection.execute(
            """SELECT type, name, sql FROM sqlite_master
            WHERE tbl_name = 'budget_reservations' AND sql IS NOT NULL
            ORDER BY type, name"""
        )
    ]
    return hashlib.sha256(
        json.dumps(
            {"objects": objects, "table_info": table_info},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _table_sql_sha256(connection: sqlite3.Connection, table: str) -> str | None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    if row is None or not isinstance(row[0], str):
        return None
    return hashlib.sha256(row[0].encode()).hexdigest()


def _schema_sha256(connection: sqlite3.Connection) -> str:
    """Fingerprint every declared schema object, excluding SQLite internals."""
    objects = [
        (row[0], row[1], row[2], " ".join(str(row[3]).split()))
        for row in connection.execute(
            """SELECT type, name, tbl_name, sql FROM sqlite_master
            WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
            ORDER BY type, name"""
        )
    ]
    return hashlib.sha256(
        json.dumps(objects, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class ResultsDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def connect_readonly(self) -> Iterator[sqlite3.Connection]:
        if not self.path.is_file():
            raise DatabaseError("database does not exist")
        try:
            connection = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            raise DatabaseError("cannot open database read-only") from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            has_schema = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_info'"
            ).fetchone()
            if has_schema is None:
                connection.executescript(SCHEMA)
                self._insert_reference_additional_grant(connection)
                connection.execute(
                    """INSERT INTO schema_info(version, applied_at)
                    VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))""",
                    (SCHEMA_VERSION,),
                )
                return
            existing = connection.execute("SELECT max(version) FROM schema_info").fetchone()[0]
            if existing == 1:
                self._migrate_v1_to_v2(connection)
                existing = 2
            if existing == 2:
                self._migrate_v2_to_v3(connection)
                existing = 3
            if existing == 3:
                self._migrate_v3_to_v4(connection)
                existing = 4
            if existing == 4:
                self._migrate_v4_to_v5(connection)
                existing = 5
            if existing == 5:
                self._migrate_v5_to_v6(connection)
                existing = 6
            if existing == 6:
                self._migrate_v6_to_v7(connection)
                existing = 7
            if existing == 7:
                self._migrate_v7_to_v8(connection)
                existing = 8
            if existing == 8:
                self._migrate_v8_to_v9(connection)
                existing = 9
            if existing == 9:
                self._migrate_v9_to_v10(connection)
                existing = 10
            if existing == 10:
                self._migrate_v10_to_v11(connection)
                existing = 11
            if existing == 11:
                self._migrate_v11_to_v12(connection)
                existing = 12
            if existing == 12:
                self._migrate_v12_to_v13(connection)
                existing = 13
            if existing == 13:
                self._migrate_v13_to_v14(connection)
                existing = 14
            if existing == 14:
                self._migrate_v14_to_v15(connection)
                existing = 15
            if existing != SCHEMA_VERSION:
                raise DatabaseError(f"database schema {existing} != supported {SCHEMA_VERSION}")

    @staticmethod
    def _insert_reference_additional_grant(connection: sqlite3.Connection) -> None:
        connection.execute(
            """INSERT INTO reference_additional_grants(
                singleton, authority_sha256, prior_settlement_receipt_sha256,
                prior_execution_scope_sha256, prior_actual_cost_usd,
                incremental_cap_usd, cumulative_cap_usd, state, created_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?, 'available',
                      strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))""",
            (
                REFERENCE_ADDITIONAL_AUTHORITY_SHA256,
                REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256,
                REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256,
                str(REFERENCE_ADDITIONAL_PRIOR_SPEND_USD),
                str(REFERENCE_ADDITIONAL_INCREMENTAL_CAP_USD),
                str(REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD),
            ),
        )

    def _migrate_v14_to_v15(self, connection: sqlite3.Connection) -> None:
        """Append the final one-shot grant after fingerprinting all v14 objects."""
        if _schema_sha256(connection) not in _V14_SCHEMA_SHA256:
            raise DatabaseError("schema v14 shape is unknown")
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """CREATE TABLE reference_additional_grants (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    authority_sha256 TEXT NOT NULL UNIQUE CHECK(length(authority_sha256) = 64),
                    prior_settlement_receipt_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(prior_settlement_receipt_sha256) = 64),
                    prior_execution_scope_sha256 TEXT NOT NULL
                        CHECK(length(prior_execution_scope_sha256) = 64),
                    prior_actual_cost_usd TEXT NOT NULL
                        CHECK(prior_actual_cost_usd = '0.00564445'),
                    incremental_cap_usd TEXT NOT NULL CHECK(incremental_cap_usd = '4.00'),
                    cumulative_cap_usd TEXT NOT NULL CHECK(cumulative_cap_usd = '4.00564445'),
                    state TEXT NOT NULL CHECK(state IN ('available', 'consumed')),
                    active_reservation_id TEXT UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    active_execution_scope_sha256 TEXT CHECK(
                        active_execution_scope_sha256 IS NULL
                        OR length(active_execution_scope_sha256) = 64
                    ),
                    reserved_at TEXT, consumed_at TEXT,
                    consumed_auth_receipt_sha256 TEXT CHECK(
                        consumed_auth_receipt_sha256 IS NULL
                        OR length(consumed_auth_receipt_sha256) = 64
                    ),
                    created_at TEXT NOT NULL,
                    CHECK((state = 'available' AND consumed_at IS NULL
                           AND consumed_auth_receipt_sha256 IS NULL)
                          OR (state = 'consumed' AND active_reservation_id IS NOT NULL
                              AND active_execution_scope_sha256 IS NOT NULL
                              AND reserved_at IS NOT NULL AND consumed_at IS NOT NULL
                              AND consumed_auth_receipt_sha256 IS NOT NULL)),
                    CHECK((active_reservation_id IS NULL
                           AND active_execution_scope_sha256 IS NULL AND reserved_at IS NULL)
                          OR (active_reservation_id IS NOT NULL
                              AND active_execution_scope_sha256 IS NOT NULL
                              AND reserved_at IS NOT NULL))
                )"""
            )
            self._insert_reference_additional_grant(connection)
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema v15 foreign-key validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (15, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
        except Exception as exc:
            raise DatabaseError(f"database schema v15 migration failed: {exc}") from exc

    def _migrate_v12_to_v13(self, connection: sqlite3.Connection) -> None:
        """Add an identity-less exact-zero settlement mode and its one-shot child slot."""
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            budget_table_exists = connection.execute(
                """SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'budget_reservations'"""
            ).fetchone()
            if budget_table_exists is None:
                raise DatabaseError("schema v12 budget-reservation ledger is missing")
            if _budget_schema_sha256(connection) not in _V12_BUDGET_SCHEMA_SHA256:
                raise DatabaseError("schema v12 budget-reservation shape is unknown")
            connection.execute("BEGIN IMMEDIATE")
            for recovery_table in (
                "reference_replacement_entitlements",
                "reference_preidentity_settlements",
            ):
                exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (recovery_table,),
                ).fetchone()
                if exists is not None:
                    if connection.execute(f"SELECT count(*) FROM {recovery_table}").fetchone()[0]:
                        raise DatabaseError(
                            "schema v13 recovery lineage already exists before migration"
                        )
                    connection.execute(f"DROP TABLE {recovery_table}")
            before = connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[0]
            connection.execute(
                """CREATE TABLE budget_reservations_v13 (
                    reservation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL UNIQUE
                        REFERENCES experiments(run_id) ON DELETE RESTRICT,
                    experiment_id TEXT NOT NULL,
                    reference_execution_scope_sha256 TEXT
                        CHECK(reference_execution_scope_sha256 IS NULL
                              OR length(reference_execution_scope_sha256) = 64),
                    trust_override_sha256 TEXT
                        CHECK(trust_override_sha256 IS NULL OR length(trust_override_sha256) = 64),
                    phase INTEGER NOT NULL CHECK(phase = 1),
                    status TEXT NOT NULL CHECK(status IN (
                        'reserved', 'submission_pending', 'submitted', 'settlement_pending',
                        'settled', 'released', 'failed', 'audit_blocked'
                    )),
                    requested_cost_usd TEXT NOT NULL,
                    provider_actual_cost_usd TEXT,
                    provider_job_id TEXT UNIQUE,
                    app_identity TEXT,
                    provider_image_identity TEXT,
                    billing_authority_sha256 TEXT,
                    authoritative_report_identity_sha256 TEXT,
                    billing_completeness_delay_seconds INTEGER,
                    submitted_at TEXT,
                    settlement_pending_at TEXT,
                    settlement_mode TEXT CHECK(
                        settlement_mode IS NULL
                        OR settlement_mode = 'workspace_zero_preidentity'
                    ),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    settlement_identity TEXT UNIQUE,
                    owner_id TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    failure_reason TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((status = 'settled' AND provider_actual_cost_usd IS NOT NULL
                           AND settlement_identity IS NOT NULL) OR status != 'settled'),
                    CHECK((settlement_mode IS NULL AND (
                              (status IN ('submitted', 'settlement_pending', 'settled')
                               AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
                              OR status NOT IN ('submitted', 'settlement_pending', 'settled')
                          )) OR (settlement_mode = 'workspace_zero_preidentity'
                                 AND status = 'settled'
                                 AND provider_job_id IS NULL AND app_identity IS NULL
                                 AND provider_image_identity IS NULL AND submitted_at IS NULL
                                 AND settlement_pending_at IS NULL
                                 AND provider_actual_cost_usd = '0')),
                    CHECK(reference_execution_scope_sha256 IS NULL
                          OR (provider_job_id IS NULL AND submitted_at IS NULL)
                          OR provider_image_identity IS NOT NULL),
                    CHECK(reference_execution_scope_sha256 IS NULL OR
                          (billing_authority_sha256 IS NOT NULL
                           AND authoritative_report_identity_sha256 IS NOT NULL
                           AND billing_completeness_delay_seconds > 0)),
                    CHECK(reference_execution_scope_sha256 IS NULL
                          OR status NOT IN ('submitted', 'settlement_pending', 'settled')
                          OR settlement_mode = 'workspace_zero_preidentity'
                          OR submitted_at IS NOT NULL),
                    CHECK(reference_execution_scope_sha256 IS NULL
                          OR status NOT IN ('settlement_pending', 'settled')
                          OR settlement_mode = 'workspace_zero_preidentity'
                          OR settlement_pending_at IS NOT NULL)
                )"""
            )
            old_columns = (
                "reservation_id, run_id, experiment_id, reference_execution_scope_sha256, "
                "trust_override_sha256, phase, status, requested_cost_usd, "
                "provider_actual_cost_usd, provider_job_id, app_identity, "
                "provider_image_identity, billing_authority_sha256, "
                "authoritative_report_identity_sha256, billing_completeness_delay_seconds, "
                "submitted_at, settlement_pending_at, idempotency_key, settlement_identity, "
                "owner_id, lease_expires_at, heartbeat_at, failure_reason, created_at, updated_at"
            )
            original_rows = connection.execute(
                f"SELECT {old_columns} FROM budget_reservations ORDER BY reservation_id"
            ).fetchall()
            connection.execute(
                f"INSERT INTO budget_reservations_v13 ({old_columns}) "
                f"SELECT {old_columns} FROM budget_reservations"
            )
            after = connection.execute("SELECT count(*) FROM budget_reservations_v13").fetchone()[0]
            if before != after:
                raise DatabaseError("schema v13 budget row-count validation failed")
            copied_rows = connection.execute(
                f"SELECT {old_columns} FROM budget_reservations_v13 ORDER BY reservation_id"
            ).fetchall()
            if [tuple(row) for row in original_rows] != [tuple(row) for row in copied_rows]:
                raise DatabaseError("schema v13 budget row-value validation failed")
            connection.execute("DROP TRIGGER IF EXISTS reference_provider_image_insert")
            connection.execute("DROP TRIGGER IF EXISTS reference_provider_image_update")
            connection.execute("DROP INDEX IF EXISTS budget_reservations_active_experiment")
            connection.execute("DROP INDEX IF EXISTS budget_reservations_reference_scope")
            connection.execute("DROP TABLE budget_reservations")
            connection.execute("ALTER TABLE budget_reservations_v13 RENAME TO budget_reservations")
            connection.execute(
                """CREATE UNIQUE INDEX budget_reservations_active_experiment
                ON budget_reservations(experiment_id)
                WHERE status IN (
                    'reserved', 'submission_pending', 'submitted',
                    'settlement_pending', 'audit_blocked'
                )"""
            )
            connection.execute(
                """CREATE INDEX budget_reservations_reference_scope
                ON budget_reservations(reference_execution_scope_sha256, status)"""
            )
            connection.execute(
                """CREATE TRIGGER reference_provider_image_insert
                BEFORE INSERT ON budget_reservations
                WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
                 AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
                 AND NEW.provider_image_identity IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'reference provider image identity required');
                END"""
            )
            connection.execute(
                """CREATE TRIGGER reference_provider_image_update
                BEFORE UPDATE ON budget_reservations
                WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
                 AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
                 AND NEW.provider_image_identity IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'reference provider image identity required');
                END"""
            )
            connection.execute(
                """CREATE TABLE reference_preidentity_settlements (
                    settlement_sha256 TEXT PRIMARY KEY CHECK(length(settlement_sha256) = 64),
                    reservation_id TEXT NOT NULL UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    recovery_authority_sha256 TEXT NOT NULL
                        CHECK(length(recovery_authority_sha256) = 64),
                    authenticated_workspace_scope_sha256 TEXT NOT NULL
                        CHECK(length(authenticated_workspace_scope_sha256) = 64),
                    auth_binding_sha256 TEXT NOT NULL CHECK(length(auth_binding_sha256) = 64),
                    pre_auth_receipt_sha256 TEXT NOT NULL
                        CHECK(length(pre_auth_receipt_sha256) = 64),
                    post_auth_receipt_sha256 TEXT NOT NULL
                        CHECK(length(post_auth_receipt_sha256) = 64),
                    billing_authority_sha256 TEXT NOT NULL
                        CHECK(length(billing_authority_sha256) = 64),
                    billing_method_sha256 TEXT NOT NULL CHECK(length(billing_method_sha256) = 64),
                    authoritative_report_identity_sha256 TEXT NOT NULL
                        CHECK(length(authoritative_report_identity_sha256) = 64),
                    original_execution_scope_sha256 TEXT NOT NULL
                        CHECK(length(original_execution_scope_sha256) = 64),
                    failure_code TEXT NOT NULL
                        CHECK(failure_code = 'auth_before_provider_identity'),
                    query_start TEXT NOT NULL, query_end TEXT NOT NULL, acquired_at TEXT NOT NULL,
                    completeness_delay_seconds INTEGER NOT NULL
                        CHECK(completeness_delay_seconds > 0),
                    actual_cost_usd TEXT NOT NULL CHECK(actual_cost_usd = '0'),
                    report_sha256 TEXT NOT NULL UNIQUE CHECK(length(report_sha256) = 64),
                    report_size_bytes INTEGER NOT NULL CHECK(report_size_bytes = 3),
                    row_count INTEGER NOT NULL CHECK(row_count = 0),
                    recorded_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE reference_replacement_entitlements (
                    entitlement_sha256 TEXT PRIMARY KEY CHECK(length(entitlement_sha256) = 64),
                    recovery_authority_sha256 TEXT NOT NULL
                        CHECK(length(recovery_authority_sha256) = 64),
                    original_reservation_id TEXT NOT NULL UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    original_execution_scope_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(original_execution_scope_sha256) = 64),
                    settlement_sha256 TEXT NOT NULL UNIQUE
                        REFERENCES reference_preidentity_settlements(settlement_sha256)
                        ON DELETE RESTRICT,
                    state TEXT NOT NULL CHECK(state IN ('available', 'consumed')),
                    replacement_reservation_id TEXT UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    replacement_execution_scope_sha256 TEXT UNIQUE
                        CHECK(replacement_execution_scope_sha256 IS NULL
                              OR length(replacement_execution_scope_sha256) = 64),
                    created_at TEXT NOT NULL,
                    consumed_at TEXT,
                    consumed_auth_receipt_sha256 TEXT
                        CHECK(consumed_auth_receipt_sha256 IS NULL
                              OR length(consumed_auth_receipt_sha256) = 64),
                    CHECK((state = 'available' AND replacement_reservation_id IS NULL
                           AND replacement_execution_scope_sha256 IS NULL
                           AND consumed_at IS NULL AND consumed_auth_receipt_sha256 IS NULL)
                          OR (state = 'consumed' AND replacement_reservation_id IS NOT NULL
                              AND replacement_execution_scope_sha256 IS NOT NULL
                              AND consumed_at IS NOT NULL
                              AND consumed_auth_receipt_sha256 IS NOT NULL))
                )"""
            )
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema v13 foreign-key validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (13, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v13 migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def _migrate_v13_to_v14(self, connection: sqlite3.Connection) -> None:
        """Replace the ambiguous scope field with a one-use, distinct-identity mapping."""
        for table, supported in _V13_RECOVERY_TABLE_SHA256.items():
            if _table_sql_sha256(connection, table) not in supported:
                raise DatabaseError(f"schema v13 recovery table shape is unknown: {table}")
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            for table in (
                "reference_replacement_entitlements",
                "reference_preidentity_settlements",
            ):
                if connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                    raise DatabaseError(
                        "schema v14 cannot infer reconciliation from existing recovery rows"
                    )
            connection.execute("DROP TABLE reference_replacement_entitlements")
            connection.execute("DROP TABLE reference_preidentity_settlements")
            connection.execute(
                """CREATE TABLE reference_workspace_scope_reconciliations (
                    authority_sha256 TEXT PRIMARY KEY CHECK(length(authority_sha256) = 64),
                    original_workspace_scope_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(original_workspace_scope_sha256) = 64),
                    authenticated_workspace_identity_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(authenticated_workspace_identity_sha256) = 64),
                    original_reservation_id TEXT NOT NULL UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    original_execution_scope_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(original_execution_scope_sha256) = 64),
                    billing_authority_sha256 TEXT NOT NULL
                        CHECK(length(billing_authority_sha256) = 64),
                    statement_sha256 TEXT NOT NULL CHECK(length(statement_sha256) = 64),
                    approved_base_commit TEXT NOT NULL CHECK(length(approved_base_commit) = 40),
                    replacement_action TEXT NOT NULL
                        CHECK(replacement_action = 'u8_reference_replacement_once'),
                    maximum_mapping_uses INTEGER NOT NULL CHECK(maximum_mapping_uses = 1),
                    recorded_at TEXT NOT NULL,
                    CHECK(
                        original_workspace_scope_sha256
                        != authenticated_workspace_identity_sha256
                    )
                )"""
            )
            connection.execute(
                """CREATE TABLE reference_preidentity_settlements (
                    settlement_sha256 TEXT PRIMARY KEY CHECK(length(settlement_sha256) = 64),
                    reservation_id TEXT NOT NULL UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    recovery_authority_sha256 TEXT NOT NULL
                        CHECK(length(recovery_authority_sha256) = 64),
                    original_workspace_scope_sha256 TEXT NOT NULL
                        CHECK(length(original_workspace_scope_sha256) = 64),
                    authenticated_workspace_identity_sha256 TEXT NOT NULL
                        CHECK(length(authenticated_workspace_identity_sha256) = 64),
                    workspace_reconciliation_authority_sha256 TEXT NOT NULL UNIQUE
                        REFERENCES reference_workspace_scope_reconciliations(authority_sha256)
                        ON DELETE RESTRICT,
                    auth_binding_sha256 TEXT NOT NULL CHECK(length(auth_binding_sha256) = 64),
                    pre_auth_receipt_sha256 TEXT NOT NULL
                        CHECK(length(pre_auth_receipt_sha256) = 64),
                    post_auth_receipt_sha256 TEXT NOT NULL
                        CHECK(length(post_auth_receipt_sha256) = 64),
                    billing_authority_sha256 TEXT NOT NULL
                        CHECK(length(billing_authority_sha256) = 64),
                    billing_method_sha256 TEXT NOT NULL CHECK(length(billing_method_sha256) = 64),
                    authoritative_report_identity_sha256 TEXT NOT NULL
                        CHECK(length(authoritative_report_identity_sha256) = 64),
                    original_execution_scope_sha256 TEXT NOT NULL
                        CHECK(length(original_execution_scope_sha256) = 64),
                    failure_code TEXT NOT NULL
                        CHECK(failure_code = 'auth_before_provider_identity'),
                    query_start TEXT NOT NULL, query_end TEXT NOT NULL, acquired_at TEXT NOT NULL,
                    completeness_delay_seconds INTEGER NOT NULL
                        CHECK(completeness_delay_seconds > 0),
                    actual_cost_usd TEXT NOT NULL CHECK(actual_cost_usd = '0'),
                    report_sha256 TEXT NOT NULL UNIQUE CHECK(length(report_sha256) = 64),
                    report_size_bytes INTEGER NOT NULL CHECK(report_size_bytes = 3),
                    row_count INTEGER NOT NULL CHECK(row_count = 0), recorded_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE reference_replacement_entitlements (
                    entitlement_sha256 TEXT PRIMARY KEY CHECK(length(entitlement_sha256) = 64),
                    recovery_authority_sha256 TEXT NOT NULL
                        CHECK(length(recovery_authority_sha256) = 64),
                    workspace_reconciliation_authority_sha256 TEXT NOT NULL UNIQUE
                        REFERENCES reference_workspace_scope_reconciliations(authority_sha256)
                        ON DELETE RESTRICT,
                    original_reservation_id TEXT NOT NULL UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    original_execution_scope_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(original_execution_scope_sha256) = 64),
                    settlement_sha256 TEXT NOT NULL UNIQUE
                        REFERENCES reference_preidentity_settlements(settlement_sha256)
                        ON DELETE RESTRICT,
                    state TEXT NOT NULL CHECK(state IN ('available', 'consumed')),
                    replacement_reservation_id TEXT UNIQUE
                        REFERENCES budget_reservations(reservation_id) ON DELETE RESTRICT,
                    replacement_execution_scope_sha256 TEXT UNIQUE CHECK(
                        replacement_execution_scope_sha256 IS NULL
                        OR length(replacement_execution_scope_sha256) = 64
                    ),
                    created_at TEXT NOT NULL, consumed_at TEXT,
                    consumed_auth_receipt_sha256 TEXT CHECK(
                        consumed_auth_receipt_sha256 IS NULL
                        OR length(consumed_auth_receipt_sha256) = 64
                    ),
                    CHECK(
                        (state = 'available' AND replacement_reservation_id IS NULL
                         AND replacement_execution_scope_sha256 IS NULL
                         AND consumed_at IS NULL AND consumed_auth_receipt_sha256 IS NULL)
                        OR (state = 'consumed' AND replacement_reservation_id IS NOT NULL
                            AND replacement_execution_scope_sha256 IS NOT NULL
                            AND consumed_at IS NOT NULL
                            AND consumed_auth_receipt_sha256 IS NOT NULL)
                    )
                )"""
            )
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema v14 foreign-key validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (14, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v14 migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def _migrate_v7_to_v8(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS provider_smoke_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    action_contract_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(action_contract_sha256) = 64),
                    execution_scope_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(execution_scope_sha256) = 64),
                    challenge_sha256 TEXT NOT NULL UNIQUE CHECK(length(challenge_sha256) = 64),
                    approval_digest TEXT NOT NULL UNIQUE CHECK(length(approval_digest) = 64),
                    contract_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'reserved', 'submission_pending', 'submission_claimed',
                        'submitted', 'settlement_pending', 'settled', 'failed', 'audit_blocked'
                    )),
                    requested_cost_usd TEXT NOT NULL CHECK(requested_cost_usd = '4.00'),
                    owner_id TEXT NOT NULL,
                    provider_call_id TEXT,
                    observation_sha256 TEXT
                        CHECK(observation_sha256 IS NULL OR length(observation_sha256) = 64),
                    observation_json TEXT,
                    settlement_pending_at TEXT,
                    settlement_identity TEXT
                        CHECK(settlement_identity IS NULL OR length(settlement_identity) = 64),
                    provider_actual_cost_usd TEXT,
                    failure_reason TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((status = 'submitted' AND provider_call_id IS NOT NULL)
                          OR status != 'submitted'),
                    CHECK((status IN ('failed', 'audit_blocked')
                           AND failure_reason IS NOT NULL)
                          OR status NOT IN ('failed', 'audit_blocked'))
                )"""
            )
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (8, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v8 migration failed: {exc}") from exc

    def _migrate_v8_to_v9(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS reference_authority_slots (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    authority_sha256 TEXT NOT NULL CHECK(
                        authority_sha256 =
                        '8be94c8db6adae0de538ca41f43e7d250b9d4b5af4ffa6cd14ee445ca45d0d61'
                    ),
                    state TEXT NOT NULL CHECK(state = 'consumed'),
                    execution_scope_sha256 TEXT NOT NULL UNIQUE
                        CHECK(length(execution_scope_sha256) = 64),
                    consumed_at TEXT NOT NULL
                )"""
            )
            if connection.execute("SELECT 1 FROM reference_authority_slots LIMIT 1").fetchone():
                raise DatabaseError("schema v9 authority-slot history is ambiguous")
            history_tables = connection.execute(
                """SELECT name FROM sqlite_master
                WHERE type = 'table' AND name IN ('budget_reservations', 'experiments')"""
            ).fetchall()
            historical = []
            if len(history_tables) == 2:
                historical = connection.execute(
                    """SELECT br.reference_execution_scope_sha256, br.status,
                        br.provider_job_id, br.submitted_at, br.created_at, br.updated_at
                    FROM budget_reservations AS br
                    JOIN experiments AS e ON e.run_id = br.run_id
                    WHERE e.mode = 'modal_reference'
                      AND (
                        br.status IN (
                            'submission_pending', 'submitted', 'settlement_pending',
                            'settled', 'failed', 'audit_blocked'
                        )
                        OR br.provider_job_id IS NOT NULL
                        OR br.submitted_at IS NOT NULL
                      )
                    ORDER BY br.reservation_id"""
                ).fetchall()
            if len(historical) > 1:
                raise DatabaseError("multiple historical reference provider contacts are ambiguous")
            if historical:
                prior = historical[0]
                scope = prior["reference_execution_scope_sha256"]
                if not isinstance(scope, str) or SHA256_RE.fullmatch(scope) is None:
                    raise DatabaseError(
                        "historical reference provider contact has no trustworthy execution scope"
                    )
                consumed_at = prior["submitted_at"] or prior["updated_at"] or prior["created_at"]
                _database_timestamp(consumed_at, "historical reference provider contact time")
                connection.execute(
                    """INSERT INTO reference_authority_slots(
                        singleton, authority_sha256, state,
                        execution_scope_sha256, consumed_at
                    ) VALUES (1, ?, 'consumed', ?, ?)""",
                    (REFERENCE_AUTHORITY_SHA256, scope, consumed_at),
                )
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (9, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v9 migration failed: {exc}") from exc

    def _migrate_v9_to_v10(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute(
                """SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'budget_reservations'"""
            ).fetchone()
            if exists is not None:
                before = connection.execute("SELECT count(*) FROM budget_reservations").fetchone()[
                    0
                ]
                connection.execute(
                    """CREATE TABLE budget_reservations_v10 (
                        reservation_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL UNIQUE
                            REFERENCES experiments(run_id) ON DELETE RESTRICT,
                        experiment_id TEXT NOT NULL,
                        reference_execution_scope_sha256 TEXT
                            CHECK(reference_execution_scope_sha256 IS NULL
                                  OR length(reference_execution_scope_sha256) = 64),
                        trust_override_sha256 TEXT
                            CHECK(trust_override_sha256 IS NULL
                                  OR length(trust_override_sha256) = 64),
                        phase INTEGER NOT NULL CHECK(phase = 1),
                        status TEXT NOT NULL CHECK(status IN (
                            'reserved', 'submission_pending', 'submitted',
                            'settlement_pending', 'settled', 'released', 'failed',
                            'audit_blocked'
                        )),
                        requested_cost_usd TEXT NOT NULL,
                        provider_actual_cost_usd TEXT,
                        provider_job_id TEXT UNIQUE,
                        app_identity TEXT,
                        billing_authority_sha256 TEXT,
                        authoritative_report_identity_sha256 TEXT,
                        billing_completeness_delay_seconds INTEGER,
                        submitted_at TEXT,
                        settlement_pending_at TEXT,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        settlement_identity TEXT UNIQUE,
                        owner_id TEXT NOT NULL,
                        lease_expires_at TEXT NOT NULL,
                        heartbeat_at TEXT NOT NULL,
                        failure_reason TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        CHECK((status = 'settled' AND provider_actual_cost_usd IS NOT NULL
                               AND settlement_identity IS NOT NULL) OR status != 'settled'),
                        CHECK((status IN ('submitted', 'settlement_pending', 'settled')
                               AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
                              OR status NOT IN ('submitted', 'settlement_pending', 'settled')),
                        CHECK(reference_execution_scope_sha256 IS NULL OR
                              (billing_authority_sha256 IS NOT NULL
                               AND authoritative_report_identity_sha256 IS NOT NULL
                               AND billing_completeness_delay_seconds > 0)),
                        CHECK(reference_execution_scope_sha256 IS NULL
                              OR status NOT IN ('submitted', 'settlement_pending', 'settled')
                              OR submitted_at IS NOT NULL),
                        CHECK(reference_execution_scope_sha256 IS NULL
                              OR status NOT IN ('settlement_pending', 'settled')
                              OR settlement_pending_at IS NOT NULL)
                    )"""
                )
                columns = (
                    "reservation_id, run_id, experiment_id, "
                    "reference_execution_scope_sha256, trust_override_sha256, phase, status, "
                    "requested_cost_usd, provider_actual_cost_usd, provider_job_id, "
                    "app_identity, billing_authority_sha256, "
                    "authoritative_report_identity_sha256, "
                    "billing_completeness_delay_seconds, submitted_at, "
                    "settlement_pending_at, idempotency_key, settlement_identity, owner_id, "
                    "lease_expires_at, heartbeat_at, failure_reason, created_at, updated_at"
                )
                connection.execute(
                    f"INSERT INTO budget_reservations_v10 ({columns}) "
                    f"SELECT {columns} FROM budget_reservations"
                )
                after = connection.execute(
                    "SELECT count(*) FROM budget_reservations_v10"
                ).fetchone()[0]
                if before != after:
                    raise DatabaseError("schema v10 budget row-count validation failed")
                connection.execute("DROP INDEX IF EXISTS budget_reservations_active_experiment")
                connection.execute("DROP INDEX IF EXISTS budget_reservations_reference_scope")
                connection.execute("DROP TABLE budget_reservations")
                connection.execute(
                    "ALTER TABLE budget_reservations_v10 RENAME TO budget_reservations"
                )
                connection.execute(
                    """CREATE UNIQUE INDEX budget_reservations_active_experiment
                    ON budget_reservations(experiment_id)
                    WHERE status IN (
                        'reserved', 'submission_pending', 'submitted',
                        'settlement_pending', 'audit_blocked'
                    )"""
                )
                connection.execute(
                    """CREATE INDEX budget_reservations_reference_scope
                    ON budget_reservations(reference_execution_scope_sha256, status)"""
                )
                if connection.execute("PRAGMA foreign_key_check('budget_reservations')").fetchall():
                    raise DatabaseError("schema v10 budget foreign-key validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (10, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v10 migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def _migrate_v10_to_v11(self, connection: sqlite3.Connection) -> None:
        """Add the identity persisted before the sole spawn without losing old evidence."""
        try:
            connection.execute("BEGIN IMMEDIATE")
            table_info = connection.execute("PRAGMA table_info(budget_reservations)").fetchall()
            columns = {row[1] for row in table_info}
            if "provider_image_identity" in columns:
                raise DatabaseError("schema v10 budget reservation shape is invalid")
            if columns:
                connection.execute(
                    "ALTER TABLE budget_reservations ADD COLUMN provider_image_identity TEXT"
                )
                contacted_reference_rows = connection.execute(
                    """SELECT count(*) FROM budget_reservations
                    WHERE reference_execution_scope_sha256 IS NOT NULL
                      AND (provider_job_id IS NOT NULL OR submitted_at IS NOT NULL)
                      AND provider_image_identity IS NULL"""
                ).fetchone()[0]
                if contacted_reference_rows:
                    raise DatabaseError(
                        "schema v10 contains contacted reference rows without image lineage"
                    )
                connection.execute(
                    """CREATE TRIGGER reference_provider_image_insert
                BEFORE INSERT ON budget_reservations
                WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
                 AND NEW.status IN ('submitted', 'settlement_pending', 'settled')
                 AND NEW.provider_image_identity IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'reference provider image identity required');
                END"""
                )
                connection.execute(
                    """CREATE TRIGGER reference_provider_image_update
                BEFORE UPDATE ON budget_reservations
                WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
                 AND NEW.status IN ('submitted', 'settlement_pending', 'settled')
                 AND NEW.provider_image_identity IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'reference provider image identity required');
                END"""
                )
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (11, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v11 migration failed: {exc}") from exc

    def _migrate_v11_to_v12(self, connection: sqlite3.Connection) -> None:
        """Require image lineage whenever durable evidence proves provider contact."""
        try:
            connection.execute("BEGIN IMMEDIATE")
            has_budget_table = connection.execute(
                """SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'budget_reservations'"""
            ).fetchone()
            if has_budget_table is not None:
                contacted_without_image = connection.execute(
                    """SELECT count(*) FROM budget_reservations
                    WHERE reference_execution_scope_sha256 IS NOT NULL
                      AND (provider_job_id IS NOT NULL OR submitted_at IS NOT NULL)
                      AND provider_image_identity IS NULL"""
                ).fetchone()[0]
                if contacted_without_image:
                    raise DatabaseError(
                        "schema v11 contains contacted reference rows without image lineage"
                    )
                connection.execute("DROP TRIGGER IF EXISTS reference_provider_image_insert")
                connection.execute("DROP TRIGGER IF EXISTS reference_provider_image_update")
                connection.execute(
                    """CREATE TRIGGER reference_provider_image_insert
                    BEFORE INSERT ON budget_reservations
                    WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
                     AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
                     AND NEW.provider_image_identity IS NULL
                    BEGIN
                        SELECT RAISE(ABORT, 'reference provider image identity required');
                    END"""
                )
                connection.execute(
                    """CREATE TRIGGER reference_provider_image_update
                    BEFORE UPDATE ON budget_reservations
                    WHEN NEW.reference_execution_scope_sha256 IS NOT NULL
                     AND (NEW.provider_job_id IS NOT NULL OR NEW.submitted_at IS NOT NULL)
                     AND NEW.provider_image_identity IS NULL
                    BEGIN
                        SELECT RAISE(ABORT, 'reference provider image identity required');
                    END"""
                )
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (12, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v12 migration failed: {exc}") from exc

    def reference_u8_slot(self, authority_sha256: str) -> dict[str, str | None]:
        if authority_sha256 != REFERENCE_AUTHORITY_SHA256:
            raise DatabaseError("reference authority is invalid")
        with self.connect_readonly() as connection:
            row = connection.execute(
                """SELECT state, execution_scope_sha256, consumed_at
                FROM reference_authority_slots WHERE singleton = 1"""
            ).fetchone()
        if row is None:
            return {
                "state": "available",
                "execution_scope_sha256": None,
                "consumed_at": None,
            }
        return dict(row)

    def reserve_provider_smoke(
        self,
        *,
        reservation_id: str,
        action_contract_sha256: str,
        execution_scope_sha256: str,
        challenge_sha256: str,
        authority_json: str,
        contract_json: str,
        owner_id: str,
        occurred_at: str,
    ) -> None:
        for label, value in (
            ("action_contract_sha256", action_contract_sha256),
            ("execution_scope_sha256", execution_scope_sha256),
            ("challenge_sha256", challenge_sha256),
        ):
            _database_sha256(value, label)
        _database_timestamp(occurred_at, "occurred_at")
        if not reservation_id or not owner_id:
            raise DatabaseError("provider smoke reservation requires identities")
        try:
            parsed = json.loads(contract_json)
            authority = json.loads(authority_json)
        except json.JSONDecodeError as exc:
            raise DatabaseError("provider smoke contract or authority is not JSON") from exc
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if canonical != contract_json:
            raise DatabaseError("provider smoke contract must be canonical JSON")
        if (
            json.dumps(authority, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            != authority_json
        ):
            raise DatabaseError("provider smoke authority must be canonical JSON")
        try:
            from lowbit_lab.provider_smoke import (
                validate_contract,
                validate_execution_authority,
            )

            contract = validate_contract(parsed)
            approval_digest = validate_execution_authority(authority, contract)
        except ValueError as exc:
            raise DatabaseError(f"provider smoke authority is invalid: {exc}") from exc
        if (
            action_contract_sha256 != contract.action_contract_sha256
            or execution_scope_sha256 != contract.execution_scope_sha256
            or challenge_sha256 != contract.challenge_sha256
        ):
            raise DatabaseError("provider smoke reservation arguments do not match authority")
        _database_private_data_scan(parsed, path="provider_smoke_contract")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            transaction_time = datetime.now(UTC)
            issued = _database_timestamp(contract.approval_issued_at, "approval_issued_at")
            expiry = _database_timestamp(contract.approval_expires_at, "approval_expires_at")
            if issued > transaction_time or expiry <= transaction_time:
                raise DatabaseError(
                    "provider smoke approval is not valid in the reservation transaction"
                )
            reconciliation_time = transaction_time.isoformat()
            connection.execute(
                """UPDATE provider_smoke_reservations
                SET status = 'audit_blocked',
                    failure_reason = 'approval_expired_with_unknown_submission_state',
                    updated_at = ?
                WHERE status IN ('submission_pending', 'submission_claimed')
                AND json_extract(contract_json, '$.approval_expires_at') <= ?""",
                (reconciliation_time, reconciliation_time),
            )
            committed = _committed_provider_cost(connection)
            if committed + REFERENCE_RESERVATION_USD > REFERENCE_RESERVATION_USD:
                raise DatabaseError("provider smoke reservation exceeds the local ledger")
            try:
                connection.execute(
                    """INSERT INTO provider_smoke_reservations(
                        reservation_id, action_contract_sha256, execution_scope_sha256,
                        challenge_sha256, approval_digest, contract_json, status,
                        requested_cost_usd, owner_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'reserved', '4.00', ?, ?, ?)""",
                    (
                        reservation_id,
                        action_contract_sha256,
                        execution_scope_sha256,
                        challenge_sha256,
                        approval_digest,
                        contract_json,
                        owner_id,
                        occurred_at,
                        occurred_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DatabaseError(
                    "provider smoke approval, scope, or contract was already consumed"
                ) from exc

    def mark_provider_smoke_submission_pending(
        self, reservation_id: str, *, owner_id: str, occurred_at: str
    ) -> None:
        self._transition_provider_smoke(
            reservation_id,
            owner_id=owner_id,
            from_status="reserved",
            to_status="submission_pending",
            occurred_at=occurred_at,
        )

    def mark_provider_smoke_submitted(
        self, reservation_id: str, *, owner_id: str, provider_call_id: str, occurred_at: str
    ) -> None:
        if not provider_call_id:
            raise DatabaseError("provider call identity is required")
        self._transition_provider_smoke(
            reservation_id,
            owner_id=owner_id,
            from_status="submission_claimed",
            to_status="submitted",
            occurred_at=occurred_at,
            provider_call_id=provider_call_id,
        )

    def claim_provider_smoke_submission(
        self,
        *,
        reservation_id: str,
        owner_id: str,
        action_contract_sha256: str,
        execution_scope_sha256: str,
        provider_environment: str,
        occurred_at: str,
    ) -> None:
        _database_timestamp(occurred_at, "occurred_at")
        expired = False
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            transaction_time = datetime.now(UTC)
            transaction_timestamp = transaction_time.isoformat()
            row = connection.execute(
                """SELECT contract_json FROM provider_smoke_reservations
                WHERE reservation_id = ? AND owner_id = ?
                AND action_contract_sha256 = ? AND execution_scope_sha256 = ?
                AND json_extract(contract_json, '$.provider_environment') = ?
                AND requested_cost_usd = '4.00' AND status = 'submission_pending'""",
                (
                    reservation_id,
                    owner_id,
                    action_contract_sha256,
                    execution_scope_sha256,
                    provider_environment,
                ),
            ).fetchone()
            if row is None:
                raise DatabaseError("provider smoke capability was already consumed or is invalid")
            contract = json.loads(row["contract_json"])
            expiry = _database_timestamp(contract.get("approval_expires_at"), "approval_expires_at")
            issued = _database_timestamp(contract.get("approval_issued_at"), "approval_issued_at")
            if issued > transaction_time or expiry <= transaction_time:
                connection.execute(
                    """UPDATE provider_smoke_reservations SET status = 'audit_blocked',
                    failure_reason = 'approval_expired_before_submission', updated_at = ?
                    WHERE reservation_id = ? AND status = 'submission_pending'""",
                    (transaction_timestamp, reservation_id),
                )
                expired = True
            else:
                cursor = connection.execute(
                    """UPDATE provider_smoke_reservations
                    SET status = 'submission_claimed', updated_at = ?
                    WHERE reservation_id = ? AND status = 'submission_pending'""",
                    (transaction_timestamp, reservation_id),
                )
                if cursor.rowcount != 1:
                    raise DatabaseError(
                        "provider smoke capability was already consumed or is invalid"
                    )
        if expired:
            raise DatabaseError("provider smoke approval expired before submission")

    def mark_provider_smoke_audit_blocked(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        reason: str,
        occurred_at: str,
        from_status: str = "submission_pending",
    ) -> None:
        if not reason:
            raise DatabaseError("audit-blocked reason is required")
        self._transition_provider_smoke(
            reservation_id,
            owner_id=owner_id,
            from_status=from_status,
            to_status="audit_blocked",
            occurred_at=occurred_at,
            failure_reason=reason[:2000],
        )

    def mark_provider_smoke_prelaunch_audited(
        self,
        reservation_id: str,
        *,
        evidence_json: str,
        evidence_sha256: str,
        occurred_at: str,
    ) -> None:
        _database_sha256(evidence_sha256, "evidence_sha256")
        _database_timestamp(occurred_at, "occurred_at")
        try:
            evidence = json.loads(evidence_json)
        except json.JSONDecodeError as exc:
            raise DatabaseError("provider smoke prelaunch evidence must be JSON") from exc
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        fields = {
            "schema_version",
            "kind",
            "reservation_id",
            "action_contract_sha256",
            "execution_scope_sha256",
            "provider_app_id",
            "provider_environment",
            "provider_app_state",
            "provider_task_count",
            "provider_container_count",
            "provider_created_at",
            "provider_stopped_at",
            "provider_report_sha256",
        }
        if (
            set(evidence) != fields
            or evidence.get("schema_version") != 1
            or evidence.get("kind") != "provider_smoke_prelaunch_audit"
            or evidence.get("reservation_id") != reservation_id
            or evidence.get("provider_environment") != "low-bit-lab"
            or evidence.get("provider_app_state") != "stopped"
            or evidence.get("provider_task_count") != 0
            or evidence.get("provider_container_count") != 0
            or not isinstance(evidence.get("provider_app_id"), str)
            or not evidence["provider_app_id"].startswith("ap-")
            or canonical != evidence_json
            or hashlib.sha256(canonical.encode()).hexdigest() != evidence_sha256
        ):
            raise DatabaseError("provider smoke prelaunch evidence is invalid")
        for field in (
            "action_contract_sha256",
            "execution_scope_sha256",
            "provider_report_sha256",
        ):
            _database_sha256(evidence.get(field), field)
        created = _database_timestamp(evidence.get("provider_created_at"), "provider_created_at")
        stopped = _database_timestamp(evidence.get("provider_stopped_at"), "provider_stopped_at")
        if stopped < created:
            raise DatabaseError("provider smoke prelaunch timestamps are invalid")
        _database_private_data_scan(evidence, path="provider_smoke_prelaunch_audit")
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE provider_smoke_reservations
                SET status = 'settlement_pending', observation_sha256 = ?,
                    observation_json = ?, settlement_pending_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'audit_blocked'
                AND provider_call_id IS NULL AND action_contract_sha256 = ?
                AND execution_scope_sha256 = ?""",
                (
                    evidence_sha256,
                    evidence_json,
                    evidence["provider_stopped_at"],
                    occurred_at,
                    reservation_id,
                    evidence["action_contract_sha256"],
                    evidence["execution_scope_sha256"],
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("provider smoke prelaunch audit transition failed")

    def mark_provider_smoke_observed(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        observation_json: str,
        observation_sha256: str,
        occurred_at: str,
    ) -> None:
        _database_sha256(observation_sha256, "observation_sha256")
        _database_timestamp(occurred_at, "occurred_at")
        try:
            observation = json.loads(observation_json)
        except json.JSONDecodeError as exc:
            raise DatabaseError("provider smoke observation must be canonical JSON") from exc
        canonical = json.dumps(
            observation, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        if (
            canonical != observation_json
            or hashlib.sha256(canonical.encode()).hexdigest() != observation_sha256
        ):
            raise DatabaseError("provider smoke observation identity mismatch")
        _database_private_data_scan(observation, path="provider_smoke_observation")
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE provider_smoke_reservations
                SET status = 'settlement_pending', observation_sha256 = ?,
                    observation_json = ?, settlement_pending_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = 'submitted'
                AND provider_call_id IS NOT NULL""",
                (
                    observation_sha256,
                    observation_json,
                    occurred_at,
                    occurred_at,
                    reservation_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("provider smoke observation transition failed")

    def settle_provider_smoke(
        self,
        reservation_id: str,
        *,
        billing_report_json: str,
        billing_report_sha256: str,
        occurred_at: str,
    ) -> dict[str, str]:
        report, actual = _reference_billing_report(billing_report_json, billing_report_sha256)
        occurred = _database_timestamp(occurred_at, "occurred_at")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT status, requested_cost_usd, provider_call_id, contract_json,
                    observation_json, settlement_pending_at FROM provider_smoke_reservations
                WHERE reservation_id = ?""",
                (reservation_id,),
            ).fetchone()
            if row is None or row["status"] != "settlement_pending":
                raise DatabaseError("provider smoke reservation cannot settle")
            contract = json.loads(row["contract_json"])
            provider_identity = row["provider_call_id"]
            if provider_identity is None and row["observation_json"] is not None:
                provider_identity = json.loads(row["observation_json"]).get("provider_app_id")
            pending_at = _database_timestamp(row["settlement_pending_at"], "settlement_pending_at")
            complete_at = pending_at + timedelta(
                seconds=contract["billing_completeness_delay_seconds"]
            )
            if (
                report["provider_job_id"] != provider_identity
                or report["billing_authority_sha256"] != contract["billing_authority_sha256"]
                or report["authoritative_report_identity_sha256"]
                != contract["authoritative_report_identity_sha256"]
                or occurred < complete_at
                or _database_timestamp(report["covered_through"], "covered_through") < complete_at
            ):
                raise DatabaseError("provider smoke billing authority is incomplete or mismatched")
            requested = _database_money(row["requested_cost_usd"], "requested_cost_usd")
            failed = actual > requested
            status = "failed" if failed else "settled"
            reason = "provider_actual_cost_exceeded_local_reservation" if failed else None
            cursor = connection.execute(
                """UPDATE provider_smoke_reservations SET status = ?,
                    provider_actual_cost_usd = ?, settlement_identity = ?,
                    failure_reason = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'settlement_pending'""",
                (
                    status,
                    format(actual, "f"),
                    billing_report_sha256,
                    reason,
                    occurred_at,
                    reservation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("provider smoke settlement transition failed")
        return {"status": status, "provider_actual_cost_usd": format(actual, "f")}

    def _transition_provider_smoke(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        from_status: str,
        to_status: str,
        occurred_at: str,
        provider_call_id: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        _database_timestamp(occurred_at, "occurred_at")
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE provider_smoke_reservations
                SET status = ?, provider_call_id = COALESCE(?, provider_call_id),
                    failure_reason = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = ?""",
                (
                    to_status,
                    provider_call_id,
                    failure_reason,
                    occurred_at,
                    reservation_id,
                    owner_id,
                    from_status,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("provider smoke state transition failed")

    def _migrate_v6_to_v7(self, connection: sqlite3.Connection) -> None:
        statements = (
            """CREATE TABLE controller_cycles (
                cycle_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                context_sha256 TEXT NOT NULL CHECK(length(context_sha256) = 64),
                authority_sha256 TEXT NOT NULL CHECK(length(authority_sha256) = 64),
                selected_action TEXT NOT NULL CHECK(selected_action = 'prepare'),
                state TEXT NOT NULL CHECK(state IN (
                    'created', 'validated', 'preparing',
                    'paid_decision_required', 'stopped', 'failed'
                )),
                owner_id TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                stop_reason TEXT,
                artifact_path TEXT,
                artifact_sha256 TEXT
                    CHECK(artifact_sha256 IS NULL OR length(artifact_sha256) = 64),
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                ended_at TEXT,
                UNIQUE(workspace_id, generation),
                CHECK((state IN ('paid_decision_required', 'stopped', 'failed')
                       AND ended_at IS NOT NULL)
                      OR (state NOT IN ('paid_decision_required', 'stopped', 'failed')
                          AND ended_at IS NULL)),
                CHECK((artifact_path IS NULL) = (artifact_sha256 IS NULL))
            )""",
            """CREATE UNIQUE INDEX controller_cycles_active_workspace
            ON controller_cycles(workspace_id)
            WHERE state IN ('created', 'validated', 'preparing')""",
            """CREATE TABLE controller_cycle_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cycle_id TEXT NOT NULL
                    REFERENCES controller_cycles(cycle_id) ON DELETE RESTRICT,
                generation INTEGER NOT NULL CHECK(generation > 0),
                from_state TEXT,
                to_state TEXT NOT NULL CHECK(to_state IN (
                    'created', 'validated', 'preparing',
                    'paid_decision_required', 'stopped', 'failed'
                )),
                reason TEXT,
                occurred_at TEXT NOT NULL
            )""",
            """CREATE INDEX controller_cycle_transitions_cycle
            ON controller_cycle_transitions(cycle_id, id)""",
        )
        try:
            connection.execute("BEGIN IMMEDIATE")
            for statement in statements:
                connection.execute(statement)
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (7, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v7 migration failed: {exc}") from exc

    def _migrate_v5_to_v6(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """ALTER TABLE budget_reservations ADD COLUMN trust_override_sha256 TEXT
                CHECK(trust_override_sha256 IS NULL OR length(trust_override_sha256) = 64)"""
            )
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (6, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise DatabaseError(f"database schema v6 migration failed: {exc}") from exc

    def _migrate_v1_to_v2(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            before = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            for statement in V2_REPLACEMENT_SCHEMA:
                connection.execute(statement)
            for table in EVIDENCE_TABLES:
                columns = V2_COPY_COLUMNS[table]
                connection.execute(
                    f"INSERT INTO {table}_v2 ({columns}) SELECT {columns} FROM {table}"
                )
            after_copy = {
                table: connection.execute(f"SELECT count(*) FROM {table}_v2").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            if before != after_copy:
                raise DatabaseError("schema migration row-count validation failed")
            for table in EVIDENCE_TABLES:
                if connection.execute(f"PRAGMA foreign_key_check('{table}_v2')").fetchall():
                    raise DatabaseError("schema migration foreign-key validation failed")

            for table in reversed(EVIDENCE_TABLES):
                connection.execute(f"DROP TABLE {table}")
            for table in EVIDENCE_TABLES:
                connection.execute(f"ALTER TABLE {table}_v2 RENAME TO {table}")
            connection.execute("CREATE INDEX experiments_config_sha ON experiments(config_sha256)")
            after_swap = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            if before != after_swap or connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema migration final validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))""",
                (2,),
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def _migrate_v2_to_v3(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            before = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            connection.execute("ALTER TABLE experiments ADD COLUMN owner_id TEXT")
            connection.execute("ALTER TABLE experiments ADD COLUMN lease_expires_at TEXT")
            connection.execute("ALTER TABLE experiments ADD COLUMN heartbeat_at TEXT")
            connection.execute(
                """CREATE TABLE activation_gates (
                    gate_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES experiments(run_id) ON DELETE RESTRICT,
                    gate_order INTEGER NOT NULL CHECK(gate_order >= 0),
                    name TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('created', 'running', 'completed', 'failed')),
                    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
                    authority_sha256 TEXT NOT NULL CHECK(length(authority_sha256) = 64),
                    evidence_sha256 TEXT
                        CHECK(evidence_sha256 IS NULL OR length(evidence_sha256) = 64),
                    evidence_json TEXT,
                    reused_gate_id TEXT
                        REFERENCES activation_gates(gate_id) ON DELETE RESTRICT,
                    owner_id TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    failure_reason TEXT,
                    evidence_valid INTEGER NOT NULL DEFAULT 1
                        CHECK(evidence_valid IN (0, 1)),
                    invalidated_at TEXT,
                    invalidation_reason TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    UNIQUE(run_id, gate_order),
                    UNIQUE(run_id, name),
                    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
                          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
                    CHECK((status = 'completed' AND evidence_sha256 IS NOT NULL
                           AND evidence_json IS NOT NULL) OR status != 'completed'),
                    CHECK((status = 'failed' AND failure_reason IS NOT NULL)
                          OR status != 'failed'),
                    CHECK((evidence_valid = 0 AND invalidated_at IS NOT NULL
                           AND invalidation_reason IS NOT NULL) OR evidence_valid = 1)
                )"""
            )
            connection.execute(
                """CREATE INDEX activation_gates_reuse
                ON activation_gates(
                    name, input_sha256, authority_sha256, status, evidence_valid
                )"""
            )
            after = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in EVIDENCE_TABLES
            }
            if before != after or connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema v3 migration validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))""",
                (3,),
            )
        except Exception as exc:
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema v3 migration failed: {exc}") from exc

    def _migrate_v3_to_v4(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            before = connection.execute("SELECT count(*) FROM experiments").fetchone()[0]
            connection.execute(
                """CREATE TABLE experiments_v4 (
                    run_id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL
                        REFERENCES experiment_configs(experiment_id) ON DELETE RESTRICT,
                    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
                    config_json TEXT NOT NULL,
                    source_hashes_json TEXT NOT NULL,
                    runtime_json TEXT NOT NULL,
                    hardware_json TEXT NOT NULL,
                    phase INTEGER NOT NULL CHECK(phase >= 0),
                    mode TEXT NOT NULL CHECK(mode IN (
                        'local_dry_run', 'modal_dry_run', 'local_activation', 'modal_reference'
                    )),
                    status TEXT NOT NULL CHECK(
                        status IN ('created', 'validated', 'running', 'completed', 'failed')
                    ),
                    modal_cost_requested_usd TEXT NOT NULL DEFAULT '0',
                    modal_cost_actual_usd TEXT NOT NULL DEFAULT '0',
                    failure_reason TEXT,
                    owner_id TEXT,
                    lease_expires_at TEXT,
                    heartbeat_at TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
                          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
                    CHECK((status = 'failed' AND failure_reason IS NOT NULL) OR status != 'failed')
                )"""
            )
            columns = (
                "run_id, experiment_id, config_sha256, config_json, source_hashes_json, "
                "runtime_json, hardware_json, phase, mode, status, modal_cost_requested_usd, "
                "modal_cost_actual_usd, failure_reason, owner_id, lease_expires_at, heartbeat_at, "
                "started_at, ended_at"
            )
            connection.execute(
                f"INSERT INTO experiments_v4 ({columns}) SELECT {columns} FROM experiments"
            )
            if connection.execute("SELECT count(*) FROM experiments_v4").fetchone()[0] != before:
                raise DatabaseError("schema v4 experiment row-count validation failed")
            connection.execute("DROP INDEX IF EXISTS experiments_config_sha")
            connection.execute("DROP TABLE experiments")
            connection.execute("ALTER TABLE experiments_v4 RENAME TO experiments")
            connection.execute("CREATE INDEX experiments_config_sha ON experiments(config_sha256)")
            migration_script = """CREATE TABLE budget_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL UNIQUE REFERENCES experiments(run_id) ON DELETE RESTRICT,
                    experiment_id TEXT NOT NULL,
                    phase INTEGER NOT NULL CHECK(phase = 1),
                    status TEXT NOT NULL CHECK(status IN (
                        'reserved', 'submitted', 'settlement_pending', 'settled',
                        'released', 'failed', 'audit_blocked'
                    )),
                    requested_cost_usd TEXT NOT NULL,
                    provider_actual_cost_usd TEXT,
                    provider_job_id TEXT UNIQUE,
                    app_identity TEXT,
                    billing_authority_sha256 TEXT,
                    authoritative_report_identity_sha256 TEXT,
                    billing_completeness_delay_seconds INTEGER,
                    submitted_at TEXT,
                    settlement_pending_at TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    settlement_identity TEXT UNIQUE,
                    owner_id TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    failure_reason TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((status = 'settled' AND provider_actual_cost_usd IS NOT NULL
                           AND settlement_identity IS NOT NULL) OR status != 'settled'),
                    CHECK((status IN (
                              'submitted', 'settlement_pending', 'settled', 'audit_blocked'
                           ) AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
                          OR status NOT IN (
                              'submitted', 'settlement_pending', 'settled', 'audit_blocked'
                          ))
                );
                CREATE UNIQUE INDEX budget_reservations_active_experiment
                ON budget_reservations(experiment_id)
                WHERE status IN ('reserved', 'submitted', 'settlement_pending', 'audit_blocked');
                CREATE TABLE reference_approval_challenges (
                    challenge_sha256 TEXT PRIMARY KEY CHECK(length(challenge_sha256) = 64),
                    packet_sha256 TEXT NOT NULL CHECK(length(packet_sha256) = 64),
                    approval_digest TEXT UNIQUE
                        CHECK(approval_digest IS NULL OR length(approval_digest) = 64),
                    expires_at TEXT,
                    consumed_at TEXT,
                    run_id TEXT REFERENCES experiments(run_id) ON DELETE RESTRICT,
                    created_at TEXT NOT NULL,
                    CHECK((approval_digest IS NULL AND expires_at IS NULL AND consumed_at IS NULL)
                          OR (approval_digest IS NOT NULL AND expires_at IS NOT NULL)),
                    CHECK(consumed_at IS NULL OR run_id IS NOT NULL)
                );"""
            for statement in migration_script.split(";"):
                if statement.strip():
                    connection.execute(statement)
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise DatabaseError("schema v4 foreign-key validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (4, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema v4 migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def _migrate_v4_to_v5(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            before = {
                "experiments": connection.execute("SELECT count(*) FROM experiments").fetchone()[0],
                "budget_reservations": connection.execute(
                    "SELECT count(*) FROM budget_reservations"
                ).fetchone()[0],
            }
            connection.execute(
                """CREATE TABLE experiments_v5 (
                    run_id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL
                        REFERENCES experiment_configs(experiment_id) ON DELETE RESTRICT,
                    config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
                    config_json TEXT NOT NULL,
                    source_hashes_json TEXT NOT NULL,
                    runtime_json TEXT NOT NULL,
                    hardware_json TEXT NOT NULL,
                    phase INTEGER NOT NULL CHECK(phase >= 0),
                    mode TEXT NOT NULL CHECK(mode IN (
                        'local_dry_run', 'modal_dry_run', 'local_activation', 'modal_reference'
                    )),
                    status TEXT NOT NULL CHECK(
                        status IN ('created', 'validated', 'running', 'completed', 'failed')
                    ),
                    modal_cost_requested_usd TEXT NOT NULL DEFAULT '0',
                    modal_cost_actual_usd TEXT DEFAULT '0',
                    failure_reason TEXT,
                    owner_id TEXT,
                    lease_expires_at TEXT,
                    heartbeat_at TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    CHECK((status IN ('completed', 'failed') AND ended_at IS NOT NULL) OR
                          (status NOT IN ('completed', 'failed') AND ended_at IS NULL)),
                    CHECK((status = 'failed' AND failure_reason IS NOT NULL)
                          OR status != 'failed'),
                    CHECK((mode = 'modal_reference'
                           AND status NOT IN ('completed', 'failed'))
                          OR modal_cost_actual_usd IS NOT NULL),
                    CHECK(mode = 'modal_reference' OR
                          (modal_cost_requested_usd = '0' AND modal_cost_actual_usd = '0'))
                )"""
            )
            experiment_columns = (
                "run_id, experiment_id, config_sha256, config_json, source_hashes_json, "
                "runtime_json, hardware_json, phase, mode, status, modal_cost_requested_usd, "
                "modal_cost_actual_usd, failure_reason, owner_id, lease_expires_at, heartbeat_at, "
                "started_at, ended_at"
            )
            connection.execute(
                f"INSERT INTO experiments_v5 ({experiment_columns}) "
                f"SELECT {experiment_columns} FROM experiments"
            )
            connection.execute(
                """CREATE TABLE budget_reservations_v5 (
                    reservation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL UNIQUE
                        REFERENCES experiments_v5(run_id) ON DELETE RESTRICT,
                    experiment_id TEXT NOT NULL,
                    reference_execution_scope_sha256 TEXT
                        CHECK(reference_execution_scope_sha256 IS NULL
                              OR length(reference_execution_scope_sha256) = 64),
                    phase INTEGER NOT NULL CHECK(phase = 1),
                    status TEXT NOT NULL CHECK(status IN (
                        'reserved', 'submitted', 'settlement_pending', 'settled',
                        'released', 'failed', 'audit_blocked'
                    )),
                    requested_cost_usd TEXT NOT NULL,
                    provider_actual_cost_usd TEXT,
                    provider_job_id TEXT UNIQUE,
                    app_identity TEXT,
                    billing_authority_sha256 TEXT,
                    authoritative_report_identity_sha256 TEXT,
                    billing_completeness_delay_seconds INTEGER,
                    submitted_at TEXT,
                    settlement_pending_at TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    settlement_identity TEXT UNIQUE,
                    owner_id TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    failure_reason TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((status = 'settled' AND provider_actual_cost_usd IS NOT NULL
                           AND settlement_identity IS NOT NULL) OR status != 'settled'),
                    CHECK((status IN (
                              'submitted', 'settlement_pending', 'settled', 'audit_blocked'
                           ) AND provider_job_id IS NOT NULL AND app_identity IS NOT NULL)
                          OR status NOT IN (
                              'submitted', 'settlement_pending', 'settled', 'audit_blocked'
                          )),
                    CHECK(reference_execution_scope_sha256 IS NULL OR
                          (billing_authority_sha256 IS NOT NULL
                           AND authoritative_report_identity_sha256 IS NOT NULL
                           AND billing_completeness_delay_seconds > 0)),
                    CHECK(reference_execution_scope_sha256 IS NULL OR status NOT IN (
                              'submitted', 'settlement_pending', 'settled', 'audit_blocked'
                          ) OR submitted_at IS NOT NULL),
                    CHECK(reference_execution_scope_sha256 IS NULL
                          OR status NOT IN ('settlement_pending', 'settled')
                          OR settlement_pending_at IS NOT NULL)
                )"""
            )
            reservation_columns = (
                "reservation_id, run_id, experiment_id, phase, status, requested_cost_usd, "
                "provider_actual_cost_usd, provider_job_id, app_identity, idempotency_key, "
                "settlement_identity, owner_id, lease_expires_at, heartbeat_at, failure_reason, "
                "created_at, updated_at"
            )
            connection.execute(
                f"INSERT INTO budget_reservations_v5 ({reservation_columns}) "
                f"SELECT {reservation_columns} FROM budget_reservations"
            )
            copied = {
                "experiments": connection.execute("SELECT count(*) FROM experiments_v5").fetchone()[
                    0
                ],
                "budget_reservations": connection.execute(
                    "SELECT count(*) FROM budget_reservations_v5"
                ).fetchone()[0],
            }
            if before != copied:
                raise DatabaseError("schema v5 row-count validation failed")
            if connection.execute("PRAGMA foreign_key_check('experiments_v5')").fetchall():
                raise DatabaseError("schema v5 foreign-key validation failed")
            if connection.execute("PRAGMA foreign_key_check('budget_reservations_v5')").fetchall():
                raise DatabaseError("schema v5 foreign-key validation failed")

            connection.execute("DROP INDEX IF EXISTS budget_reservations_active_experiment")
            connection.execute("DROP TABLE budget_reservations")
            connection.execute("DROP INDEX IF EXISTS experiments_config_sha")
            connection.execute("DROP TABLE experiments")
            connection.execute("ALTER TABLE experiments_v5 RENAME TO experiments")
            connection.execute("ALTER TABLE budget_reservations_v5 RENAME TO budget_reservations")
            connection.execute("CREATE INDEX experiments_config_sha ON experiments(config_sha256)")
            connection.execute(
                """CREATE UNIQUE INDEX budget_reservations_active_experiment
                ON budget_reservations(experiment_id)
                WHERE status IN ('reserved', 'submitted', 'settlement_pending', 'audit_blocked')"""
            )
            connection.execute(
                """CREATE INDEX budget_reservations_reference_scope
                ON budget_reservations(reference_execution_scope_sha256, status)"""
            )
            if (
                before
                != {
                    "experiments": connection.execute(
                        "SELECT count(*) FROM experiments"
                    ).fetchone()[0],
                    "budget_reservations": connection.execute(
                        "SELECT count(*) FROM budget_reservations"
                    ).fetchone()[0],
                }
                or connection.execute("PRAGMA foreign_key_check").fetchall()
            ):
                raise DatabaseError("schema v5 final validation failed")
            connection.execute(
                """INSERT INTO schema_info(version, applied_at)
                VALUES (5, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"""
            )
            connection.commit()
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(f"database schema v5 migration failed: {exc}") from exc
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    def acquire_controller_cycle(
        self,
        *,
        cycle_id: str,
        workspace_id: str,
        owner_id: str,
        context_sha256: str,
        authority_sha256: str,
        started_at: str,
        lease_expires_at: str,
        selected_action: str = "prepare",
    ) -> int:
        cycle_id = _controller_identifier(cycle_id, "cycle_id")
        workspace_id = _controller_identifier(workspace_id, "workspace_id")
        owner_id = _controller_identifier(owner_id, "owner_id")
        context_sha256 = _database_sha256(context_sha256, "context_sha256")
        authority_sha256 = _database_sha256(authority_sha256, "authority_sha256")
        started = _database_timestamp(started_at, "started_at")
        lease = _database_timestamp(lease_expires_at, "lease_expires_at")
        if selected_action != "prepare":
            raise DatabaseError("controller selected_action is not allowed")
        if lease <= started:
            raise DatabaseError("controller lease must expire after start")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            expired = connection.execute(
                """SELECT cycle_id, generation, state FROM controller_cycles
                WHERE workspace_id = ? AND state IN ('created', 'validated', 'preparing')
                  AND lease_expires_at <= ?""",
                (workspace_id, started_at),
            ).fetchall()
            for row in expired:
                reason = "controller cycle lease expired before terminal persistence"
                connection.execute(
                    """UPDATE controller_cycles SET state = 'failed', stop_reason = ?,
                    heartbeat_at = ?, updated_at = ?, ended_at = ? WHERE cycle_id = ?""",
                    (reason, started_at, started_at, started_at, row["cycle_id"]),
                )
                connection.execute(
                    """INSERT INTO controller_cycle_transitions(
                    cycle_id, generation, from_state, to_state, reason, occurred_at
                    ) VALUES (?, ?, ?, 'failed', ?, ?)""",
                    (row["cycle_id"], row["generation"], row["state"], reason, started_at),
                )
            active = connection.execute(
                """SELECT cycle_id FROM controller_cycles
                WHERE workspace_id = ? AND state IN ('created', 'validated', 'preparing')""",
                (workspace_id,),
            ).fetchone()
            if active is not None:
                raise DatabaseError(
                    f"controller workspace already has an active cycle: {active['cycle_id']}"
                )
            generation = connection.execute(
                "SELECT coalesce(max(generation), 0) + 1 FROM controller_cycles "
                "WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()[0]
            connection.execute(
                """INSERT INTO controller_cycles(
                    cycle_id, workspace_id, generation, context_sha256, authority_sha256,
                    selected_action, state, owner_id, lease_expires_at, heartbeat_at,
                    started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'created', ?, ?, ?, ?, ?)""",
                (
                    cycle_id,
                    workspace_id,
                    generation,
                    context_sha256,
                    authority_sha256,
                    selected_action,
                    owner_id,
                    lease_expires_at,
                    started_at,
                    started_at,
                    started_at,
                ),
            )
            connection.execute(
                """INSERT INTO controller_cycle_transitions(
                    cycle_id, generation, from_state, to_state, occurred_at
                ) VALUES (?, ?, NULL, 'created', ?)""",
                (cycle_id, generation, started_at),
            )
            return generation

    def transition_controller_cycle(
        self,
        cycle_id: str,
        *,
        owner_id: str,
        generation: int,
        context_sha256: str,
        authority_sha256: str,
        from_state: str,
        to_state: str,
        occurred_at: str,
        lease_expires_at: str | None = None,
        reason: str | None = None,
        stop_reason: str | None = None,
    ) -> None:
        cycle_id = _controller_identifier(cycle_id, "cycle_id")
        owner_id = _controller_identifier(owner_id, "owner_id")
        context_sha256 = _database_sha256(context_sha256, "context_sha256")
        authority_sha256 = _database_sha256(authority_sha256, "authority_sha256")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
            raise DatabaseError("controller generation must be a positive integer")
        if to_state not in CONTROLLER_TRANSITIONS.get(from_state, set()):
            raise DatabaseError(f"invalid controller transition: {from_state} -> {to_state}")
        if to_state in CONTROLLER_TERMINAL_STATES and to_state != "failed":
            raise DatabaseError("terminal controller transitions require finalize")
        occurred = _database_timestamp(occurred_at, "occurred_at")
        if reason is not None:
            reason = _controller_text(reason, "reason", maximum=1024)
        if to_state == "failed":
            if reason is not None or stop_reason is None:
                raise DatabaseError("failed controller transition requires only stop_reason")
            stop_reason = _controller_text(stop_reason, "stop_reason", maximum=1024)
        elif stop_reason is not None:
            raise DatabaseError("nonterminal controller transition cannot set stop_reason")
        new_lease = None
        if lease_expires_at is not None:
            new_lease = _database_timestamp(lease_expires_at, "lease_expires_at")
            if new_lease <= occurred:
                raise DatabaseError("controller lease must expire after transition")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT lease_expires_at, heartbeat_at FROM controller_cycles
                WHERE cycle_id = ? AND owner_id = ? AND generation = ?
                  AND context_sha256 = ? AND authority_sha256 = ? AND state = ?""",
                (
                    cycle_id,
                    owner_id,
                    generation,
                    context_sha256,
                    authority_sha256,
                    from_state,
                ),
            ).fetchone()
            if row is None:
                raise DatabaseError(f"controller cycle transition lost ownership: {cycle_id}")
            stored_lease = _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
            if stored_lease <= occurred:
                raise DatabaseError(f"controller cycle lease has expired: {cycle_id}")
            stored_heartbeat = _database_timestamp(row["heartbeat_at"], "stored heartbeat_at")
            if occurred < stored_heartbeat:
                raise DatabaseError("controller transition cannot predate its heartbeat")
            next_lease = (
                lease_expires_at if lease_expires_at is not None else row["lease_expires_at"]
            )
            if to_state == "failed":
                cursor = connection.execute(
                    """UPDATE controller_cycles SET state = 'failed', stop_reason = ?,
                        lease_expires_at = ?, heartbeat_at = ?, updated_at = ?, ended_at = ?
                    WHERE cycle_id = ? AND owner_id = ? AND generation = ?
                      AND context_sha256 = ? AND authority_sha256 = ? AND state = ?""",
                    (
                        stop_reason,
                        next_lease,
                        occurred_at,
                        occurred_at,
                        occurred_at,
                        cycle_id,
                        owner_id,
                        generation,
                        context_sha256,
                        authority_sha256,
                        from_state,
                    ),
                )
            else:
                cursor = connection.execute(
                    """UPDATE controller_cycles SET state = ?, lease_expires_at = ?,
                        heartbeat_at = ?, updated_at = ?
                    WHERE cycle_id = ? AND owner_id = ? AND generation = ?
                      AND context_sha256 = ? AND authority_sha256 = ? AND state = ?""",
                    (
                        to_state,
                        next_lease,
                        occurred_at,
                        occurred_at,
                        cycle_id,
                        owner_id,
                        generation,
                        context_sha256,
                        authority_sha256,
                        from_state,
                    ),
                )
            if cursor.rowcount != 1:
                raise DatabaseError(f"controller cycle transition lost ownership: {cycle_id}")
            connection.execute(
                """INSERT INTO controller_cycle_transitions(
                    cycle_id, generation, from_state, to_state, reason, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    cycle_id,
                    generation,
                    from_state,
                    to_state,
                    stop_reason if to_state == "failed" else reason,
                    occurred_at,
                ),
            )

    def finalize_controller_cycle(
        self,
        cycle_id: str,
        *,
        owner_id: str,
        generation: int,
        context_sha256: str,
        authority_sha256: str,
        from_state: str,
        to_state: str,
        occurred_at: str,
        stop_reason: str,
        artifact_path: str,
        artifact_sha256: str,
    ) -> None:
        cycle_id = _controller_identifier(cycle_id, "cycle_id")
        owner_id = _controller_identifier(owner_id, "owner_id")
        context_sha256 = _database_sha256(context_sha256, "context_sha256")
        authority_sha256 = _database_sha256(authority_sha256, "authority_sha256")
        artifact_sha256 = _database_sha256(artifact_sha256, "artifact_sha256")
        artifact_path = _controller_artifact_path(artifact_path)
        stop_reason = _controller_text(stop_reason, "stop_reason", maximum=1024)
        if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
            raise DatabaseError("controller generation must be a positive integer")
        if to_state not in CONTROLLER_TERMINAL_STATES or to_state not in CONTROLLER_TRANSITIONS.get(
            from_state, set()
        ):
            raise DatabaseError(f"invalid controller finalization: {from_state} -> {to_state}")
        occurred = _database_timestamp(occurred_at, "occurred_at")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT lease_expires_at, heartbeat_at FROM controller_cycles
                WHERE cycle_id = ? AND owner_id = ? AND generation = ?
                  AND context_sha256 = ? AND authority_sha256 = ? AND state = ?""",
                (
                    cycle_id,
                    owner_id,
                    generation,
                    context_sha256,
                    authority_sha256,
                    from_state,
                ),
            ).fetchone()
            if row is None:
                raise DatabaseError(f"controller cycle finalization lost ownership: {cycle_id}")
            if _database_timestamp(row["lease_expires_at"], "stored lease_expires_at") <= occurred:
                raise DatabaseError(f"controller cycle lease has expired: {cycle_id}")
            if occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at"):
                raise DatabaseError("controller finalization cannot predate its heartbeat")
            cursor = connection.execute(
                """UPDATE controller_cycles SET state = ?, stop_reason = ?, artifact_path = ?,
                    artifact_sha256 = ?, heartbeat_at = ?, updated_at = ?, ended_at = ?
                WHERE cycle_id = ? AND owner_id = ? AND generation = ?
                  AND context_sha256 = ? AND authority_sha256 = ? AND state = ?""",
                (
                    to_state,
                    stop_reason,
                    artifact_path,
                    artifact_sha256,
                    occurred_at,
                    occurred_at,
                    occurred_at,
                    cycle_id,
                    owner_id,
                    generation,
                    context_sha256,
                    authority_sha256,
                    from_state,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"controller cycle finalization lost ownership: {cycle_id}")
            connection.execute(
                """INSERT INTO controller_cycle_transitions(
                    cycle_id, generation, from_state, to_state, reason, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (cycle_id, generation, from_state, to_state, stop_reason, occurred_at),
            )

    def fail_controller_cycle(
        self,
        cycle_id: str,
        *,
        owner_id: str,
        generation: int,
        context_sha256: str,
        authority_sha256: str,
        from_state: str,
        occurred_at: str,
        stop_reason: str,
    ) -> None:
        cycle_id = _controller_identifier(cycle_id, "cycle_id")
        owner_id = _controller_identifier(owner_id, "owner_id")
        context_sha256 = _database_sha256(context_sha256, "context_sha256")
        authority_sha256 = _database_sha256(authority_sha256, "authority_sha256")
        stop_reason = _controller_text(stop_reason, "stop_reason", maximum=1024)
        if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
            raise DatabaseError("controller generation must be a positive integer")
        if "failed" not in CONTROLLER_TRANSITIONS.get(from_state, set()):
            raise DatabaseError(f"invalid controller failure: {from_state} -> failed")
        occurred = _database_timestamp(occurred_at, "occurred_at")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT lease_expires_at FROM controller_cycles
                WHERE cycle_id = ? AND owner_id = ? AND generation = ?
                  AND context_sha256 = ? AND authority_sha256 = ? AND state = ?""",
                (
                    cycle_id,
                    owner_id,
                    generation,
                    context_sha256,
                    authority_sha256,
                    from_state,
                ),
            ).fetchone()
            if (
                row is None
                or _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
                <= occurred
            ):
                raise DatabaseError(f"controller cycle failure lost ownership: {cycle_id}")
            cursor = connection.execute(
                """UPDATE controller_cycles SET state = 'failed', stop_reason = ?,
                heartbeat_at = ?, updated_at = ?, ended_at = ?
                WHERE cycle_id = ? AND owner_id = ? AND generation = ?
                  AND context_sha256 = ? AND authority_sha256 = ? AND state = ?""",
                (
                    stop_reason,
                    occurred_at,
                    occurred_at,
                    occurred_at,
                    cycle_id,
                    owner_id,
                    generation,
                    context_sha256,
                    authority_sha256,
                    from_state,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"controller cycle failure lost ownership: {cycle_id}")
            connection.execute(
                """INSERT INTO controller_cycle_transitions(
                cycle_id, generation, from_state, to_state, reason, occurred_at
                ) VALUES (?, ?, ?, 'failed', ?, ?)""",
                (cycle_id, generation, from_state, stop_reason, occurred_at),
            )

    def get_controller_cycle(self, cycle_id: str) -> dict[str, Any]:
        cycle_id = _controller_identifier(cycle_id, "cycle_id")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM controller_cycles WHERE cycle_id = ?", (cycle_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown controller cycle: {cycle_id}")
            transitions = connection.execute(
                """SELECT from_state, to_state, reason, occurred_at
                FROM controller_cycle_transitions WHERE cycle_id = ? ORDER BY id""",
                (cycle_id,),
            ).fetchall()
        result = dict(row)
        result["transitions"] = [dict(item) for item in transitions]
        return result

    def get_latest_controller_cycle(self, workspace_id: str) -> dict[str, Any] | None:
        workspace_id = _controller_identifier(workspace_id, "workspace_id")
        with self.connect() as connection:
            row = connection.execute(
                """SELECT * FROM controller_cycles
                WHERE workspace_id = ? ORDER BY generation DESC LIMIT 1""",
                (workspace_id,),
            ).fetchone()
            if row is None:
                return None
            transitions = connection.execute(
                """SELECT from_state, to_state, reason, occurred_at
                FROM controller_cycle_transitions WHERE cycle_id = ? ORDER BY id""",
                (row["cycle_id"],),
            ).fetchall()
        result = dict(row)
        result["transitions"] = [dict(item) for item in transitions]
        return result

    def get_latest_controller_cycle_readonly(self, workspace_id: str) -> dict[str, Any] | None:
        workspace_id = _controller_identifier(workspace_id, "workspace_id")
        try:
            with self.connect_readonly() as connection:
                row = connection.execute(
                    """SELECT * FROM controller_cycles
                    WHERE workspace_id = ? ORDER BY generation DESC LIMIT 1""",
                    (workspace_id,),
                ).fetchone()
                if row is None:
                    return None
                transitions = connection.execute(
                    """SELECT from_state, to_state, reason, occurred_at
                    FROM controller_cycle_transitions WHERE cycle_id = ? ORDER BY id""",
                    (row["cycle_id"],),
                ).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError("cannot read controller cycle") from exc
        result = dict(row)
        result["transitions"] = [dict(item) for item in transitions]
        return result

    def reconcile_stale_controller_cycles(self, *, now: str) -> list[str]:
        now_time = _database_timestamp(now, "now")
        reason = "controller cycle lease expired before terminal persistence"
        reconciled: list[str] = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT cycle_id, generation, state, lease_expires_at
                FROM controller_cycles
                WHERE state IN ('created', 'validated', 'preparing') ORDER BY cycle_id"""
            ).fetchall()
            for row in rows:
                stored_lease = _database_timestamp(
                    row["lease_expires_at"], "stored lease_expires_at"
                )
                if stored_lease > now_time:
                    continue
                cursor = connection.execute(
                    """UPDATE controller_cycles SET state = 'failed', stop_reason = ?,
                        heartbeat_at = ?, updated_at = ?, ended_at = ?
                    WHERE cycle_id = ? AND generation = ? AND state = ?""",
                    (
                        reason,
                        now,
                        now,
                        now,
                        row["cycle_id"],
                        row["generation"],
                        row["state"],
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                connection.execute(
                    """INSERT INTO controller_cycle_transitions(
                        cycle_id, generation, from_state, to_state, reason, occurred_at
                    ) VALUES (?, ?, ?, 'failed', ?, ?)""",
                    (row["cycle_id"], row["generation"], row["state"], reason, now),
                )
                reconciled.append(row["cycle_id"])
        return reconciled

    def create_run(
        self,
        *,
        run_id: str,
        experiment_id: str,
        config_sha256: str,
        config_json: str,
        source_hashes: dict[str, str],
        runtime: dict[str, Any],
        hardware: dict[str, Any],
        phase: int,
        mode: str,
        requested_cost: str,
        started_at: str,
        owner_id: str | None = None,
        lease_expires_at: str | None = None,
        heartbeat_at: str | None = None,
        attempt_id: str | None = None,
    ) -> None:
        if mode == "local_activation":
            _validate_activation_run_config(config_json, requested_cost)
        if mode == "modal_reference":
            raise DatabaseError("modal_reference runs require an atomic budget reservation")
        with self.connect() as connection:
            registered = connection.execute(
                "SELECT config_sha256, config_json FROM experiment_configs WHERE experiment_id = ?",
                (experiment_id,),
            ).fetchone()
            if registered is None:
                connection.execute(
                    """INSERT INTO experiment_configs(experiment_id, config_sha256, config_json)
                    VALUES (?, ?, ?)""",
                    (experiment_id, config_sha256, config_json),
                )
            elif (
                registered["config_sha256"] != config_sha256
                or registered["config_json"] != config_json
            ):
                raise DatabaseError(
                    f"experiment_id is already bound to a different config: {experiment_id}"
                )
            connection.execute(
                """INSERT INTO experiments(
                    run_id, experiment_id, config_sha256, config_json, source_hashes_json,
                    runtime_json, hardware_json, phase, mode, status,
                    modal_cost_requested_usd, modal_cost_actual_usd, owner_id,
                    lease_expires_at, heartbeat_at, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, '0', ?, ?, ?, ?)""",
                (
                    run_id,
                    experiment_id,
                    config_sha256,
                    config_json,
                    json.dumps(source_hashes, sort_keys=True, separators=(",", ":")),
                    json.dumps(runtime, sort_keys=True, separators=(",", ":")),
                    json.dumps(hardware, sort_keys=True, separators=(",", ":")),
                    phase,
                    mode,
                    requested_cost,
                    owner_id,
                    lease_expires_at,
                    heartbeat_at,
                    started_at,
                ),
            )
            connection.execute(
                """INSERT INTO state_transitions(run_id, from_state, to_state)
                VALUES (?, NULL, 'created')""",
                (run_id,),
            )
            if attempt_id is not None:
                cursor = connection.execute(
                    """UPDATE attempts SET status = 'linked', run_id = ?, ended_at = ?
                    WHERE attempt_id = ? AND status = 'received'""",
                    (run_id, started_at, attempt_id),
                )
                if cursor.rowcount != 1:
                    raise DatabaseError(f"attempt cannot be linked: {attempt_id}")

    def create_activation_gates(
        self,
        *,
        run_id: str,
        owner_id: str,
        lease_expires_at: str,
        heartbeat_at: str,
        started_at: str,
        gates: list[dict[str, Any]],
    ) -> None:
        if not owner_id or not gates:
            raise DatabaseError("activation gates require an owner and a non-empty plan")
        with self.connect() as connection:
            parent = connection.execute(
                "SELECT mode, status, owner_id FROM experiments WHERE run_id = ?", (run_id,)
            ).fetchone()
            if (
                parent is None
                or parent["mode"] != "local_activation"
                or parent["status"] in TERMINAL_STATES
                or parent["owner_id"] != owner_id
            ):
                raise DatabaseError("activation gate parent is not owned and active")
            for order, gate in enumerate(gates):
                connection.execute(
                    """INSERT INTO activation_gates(
                        gate_id, run_id, gate_order, name, status, input_sha256,
                        authority_sha256, owner_id, lease_expires_at, heartbeat_at, started_at
                    ) VALUES (?, ?, ?, ?, 'created', ?, ?, ?, ?, ?, ?)""",
                    (
                        gate["gate_id"],
                        run_id,
                        order,
                        gate["name"],
                        gate["input_sha256"],
                        gate["authority_sha256"],
                        owner_id,
                        lease_expires_at,
                        heartbeat_at,
                        started_at,
                    ),
                )

    def reserve_reference_run(
        self,
        *,
        reservation_id: str,
        attempt_id: str,
        run_id: str,
        experiment_id: str,
        config_sha256: str,
        config_json: str,
        source_hashes: dict[str, str],
        runtime: dict[str, Any],
        hardware: dict[str, Any],
        requested_cost_usd: str,
        phase_cap_usd: str,
        total_cap_usd: str,
        single_job_cap_usd: str,
        idempotency_key: str,
        owner_id: str,
        lease_expires_at: str,
        started_at: str,
        challenge_sha256: str,
        approval_digest: str,
        standing_authority_sha256: str,
        bootstrap_authority_sha256: str,
        authority_root: Path,
        standing_packet_sha256: str | None = None,
        approval_expires_at: str | None = None,
        attempt_config_path: str | None = None,
        attempt_raw_config_sha256: str | None = None,
        authority_path: Path = AUTHORITY_PATH,
        bootstrap_authority_path: Path = BOOTSTRAP_AUTHORITY_PATH,
        replacement_entitlement_sha256: str | None = None,
        recovery_authority_sha256: str | None = None,
        recovery_authority_path: Path = RECOVERY_AUTHORITY_PATH,
        additional_authority_sha256: str | None = None,
        additional_prior_settlement_receipt_sha256: str | None = None,
        additional_prior_execution_scope_sha256: str | None = None,
        additional_authority_path: Path = ADDITIONAL_AUTHORITY_PATH,
    ) -> None:
        requested = _database_money(requested_cost_usd, "requested_cost_usd")
        phase_cap = _database_money(phase_cap_usd, "phase_cap_usd")
        total_cap = _database_actual_money(total_cap_usd, "total_cap_usd")
        single_job_cap = _database_money(single_job_cap_usd, "single_job_cap_usd")
        additional_mode = any(
            value is not None
            for value in (
                additional_authority_sha256,
                additional_prior_settlement_receipt_sha256,
                additional_prior_execution_scope_sha256,
            )
        )
        expected_total_cap = (
            REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD
            if additional_mode
            else REFERENCE_CUMULATIVE_CAP_USD
        )
        if (
            requested != REFERENCE_RESERVATION_USD
            or single_job_cap != REFERENCE_RESERVATION_USD
            or phase_cap != REFERENCE_RESERVATION_USD
            or total_cap != expected_total_cap
        ):
            raise DatabaseError(
                "reference reservation, phase, and single-job caps must equal USD 4.00 "
                f"and cumulative cap must equal USD {expected_total_cap}"
            )
        if standing_authority_sha256 != REFERENCE_AUTHORITY_SHA256:
            raise DatabaseError("reference standing authority is invalid")
        if bootstrap_authority_sha256 != REFERENCE_BOOTSTRAP_AUTHORITY_SHA256:
            raise DatabaseError("reference bootstrap authority is invalid")
        replacement_mode = replacement_entitlement_sha256 is not None
        if additional_mode and replacement_mode:
            raise DatabaseError("reference additional and replacement authorities are exclusive")
        additional_lineage = (
            additional_authority_sha256,
            additional_prior_settlement_receipt_sha256,
            additional_prior_execution_scope_sha256,
        )
        if additional_mode and not all(value is not None for value in additional_lineage):
            raise DatabaseError("reference additional authority is incomplete")
        if additional_mode:
            _database_sha256(additional_authority_sha256, "additional_authority_sha256")
            _database_sha256(
                additional_prior_settlement_receipt_sha256,
                "additional_prior_settlement_receipt_sha256",
            )
            _database_sha256(
                additional_prior_execution_scope_sha256,
                "additional_prior_execution_scope_sha256",
            )
            if (
                additional_authority_sha256 != REFERENCE_ADDITIONAL_AUTHORITY_SHA256
                or additional_prior_settlement_receipt_sha256
                != REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256
                or additional_prior_execution_scope_sha256
                != REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256
            ):
                raise DatabaseError("reference additional authority lineage is invalid")
        if replacement_mode != (recovery_authority_sha256 is not None):
            raise DatabaseError("reference replacement authority is incomplete")
        if replacement_mode:
            _database_sha256(replacement_entitlement_sha256, "replacement_entitlement_sha256")
            if recovery_authority_sha256 != REFERENCE_RECOVERY_AUTHORITY_SHA256:
                raise DatabaseError("reference recovery authority is invalid")
        try:
            validated_authority_sha256 = validate_reference_authority(
                authority_root, authority_path
            )
            validated_bootstrap_sha256 = validate_reference_bootstrap_authority(
                authority_root, bootstrap_authority_path
            )
            validated_recovery_sha256 = (
                validate_reference_recovery_authority(authority_root, recovery_authority_path)
                if replacement_mode
                else None
            )
            validated_additional_sha256 = (
                validate_reference_additional_authority(authority_root, additional_authority_path)
                if additional_mode
                else None
            )
        except ReferenceAuthorityError as exc:
            raise DatabaseError(
                "reference standing or bootstrap authority files are invalid"
            ) from exc
        if validated_authority_sha256 != standing_authority_sha256:
            raise DatabaseError("reference standing authority digest does not match its files")
        if validated_bootstrap_sha256 != bootstrap_authority_sha256:
            raise DatabaseError("reference bootstrap authority digest does not match its files")
        if replacement_mode and validated_recovery_sha256 != recovery_authority_sha256:
            raise DatabaseError("reference recovery authority digest does not match its files")
        if additional_mode and validated_additional_sha256 != additional_authority_sha256:
            raise DatabaseError("reference additional authority digest does not match its files")
        if not owner_id or not idempotency_key:
            raise DatabaseError("reference reservation requires owner and idempotency key")
        standing_setup = (
            standing_packet_sha256,
            approval_expires_at,
            attempt_config_path,
            attempt_raw_config_sha256,
        )
        if any(value is not None for value in standing_setup) and not all(
            value is not None for value in standing_setup
        ):
            raise DatabaseError("standing reference approval setup is incomplete")
        if standing_packet_sha256 is not None:
            _database_sha256(standing_packet_sha256, "standing_packet_sha256")
            _database_sha256(attempt_raw_config_sha256, "attempt_raw_config_sha256")
            if (
                not isinstance(attempt_config_path, str)
                or Path(attempt_config_path).is_absolute()
                or ".." in Path(attempt_config_path).parts
                or not Path(attempt_config_path).as_posix().startswith("configs/local/")
            ):
                raise DatabaseError("standing reference attempt path is invalid")
        _database_sha256(challenge_sha256, "challenge_sha256")
        _database_sha256(approval_digest, "approval_digest")
        expected_challenge, parsed_config = _reference_challenge(config_json, config_sha256)
        if expected_challenge != challenge_sha256:
            raise DatabaseError("reference approval is not bound to the canonical config")
        inputs = parsed_config.get("inputs")
        if not isinstance(inputs, dict):
            raise DatabaseError("reference config inputs are incomplete")
        expected_sources = {
            name: value
            for name, value in inputs.items()
            if name not in {"weight_inventory_tensor_bytes", "evaluation_max_context_tokens"}
            and value is not None
        }
        if source_hashes != expected_sources:
            raise DatabaseError("reference source lineage does not match the canonical config")
        if runtime != {"receipt_sha256": inputs.get("runtime_receipt_sha256")}:
            raise DatabaseError("reference runtime lineage does not match the canonical config")
        try:
            execution_scope_sha256 = reference_execution_scope_sha256(
                source_revision=str(inputs["source_revision"]),
                weight_inventory_sha256=str(inputs["weight_inventory_sha256"]),
                evaluation_lock_sha256=str(inputs["evaluation_lock_sha256"]),
                formula_authority_sha256=str(inputs["formula_authority_sha256"]),
                formula_approval_sha256=str(parsed_config["gates"]["formula_approval_sha256"]),
                trust_override_sha256=str(parsed_config["provider"]["trust_override_sha256"]),
            )
        except ValueError as exc:
            raise DatabaseError(f"reference execution scope is invalid: {exc}") from exc
        for label, value in (
            ("config", parsed_config),
            ("source_hashes", source_hashes),
            ("runtime", runtime),
            ("hardware", hardware),
        ):
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode()) > 1_000_000:
                raise DatabaseError(f"reference {label} exceeds the audit record limit")
            _database_private_data_scan(value, path=label)
        start_time = _database_timestamp(started_at, "started_at")
        initial_lease_expiry = _database_timestamp(lease_expires_at, "lease_expires_at")
        if initial_lease_expiry <= start_time:
            raise DatabaseError("reference reservation lease must expire after it starts")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if standing_packet_sha256 is not None:
                approval_expiry = _database_timestamp(approval_expires_at, "approval_expires_at")
                if approval_expiry <= start_time or initial_lease_expiry > approval_expiry:
                    raise DatabaseError("standing reference approval expiry is invalid")
                connection.execute(
                    """INSERT INTO reference_approval_challenges(
                        challenge_sha256, packet_sha256, approval_digest, expires_at, created_at
                    ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        challenge_sha256,
                        standing_packet_sha256,
                        approval_digest,
                        approval_expires_at,
                        started_at,
                    ),
                )
                connection.execute(
                    """INSERT INTO attempts(
                        attempt_id, config_path, raw_config_sha256, status, started_at
                    ) VALUES (?, ?, ?, 'received', ?)""",
                    (
                        attempt_id,
                        attempt_config_path,
                        attempt_raw_config_sha256,
                        started_at,
                    ),
                )
            approval = connection.execute(
                """SELECT approval_digest, expires_at, consumed_at
                FROM reference_approval_challenges WHERE challenge_sha256 = ?""",
                (challenge_sha256,),
            ).fetchone()
            if (
                approval is None
                or approval["approval_digest"] != approval_digest
                or approval["consumed_at"] is not None
                or approval["expires_at"] is None
                or _database_timestamp(approval["expires_at"], "expires_at") <= start_time
                or initial_lease_expiry > _database_timestamp(approval["expires_at"], "expires_at")
            ):
                raise DatabaseError(
                    "reference approval is missing, expired, mismatched, or consumed"
                )
            replacement = None
            if replacement_mode:
                replacement = connection.execute(
                    """SELECT original_reservation_id, original_execution_scope_sha256
                    FROM reference_replacement_entitlements
                    WHERE entitlement_sha256 = ? AND recovery_authority_sha256 = ?
                      AND state = 'available'""",
                    (replacement_entitlement_sha256, recovery_authority_sha256),
                ).fetchone()
                if replacement is None:
                    raise DatabaseError("reference replacement entitlement is unavailable")
            additional_grant = None
            if additional_mode:
                additional_grant = connection.execute(
                    """SELECT * FROM reference_additional_grants
                    WHERE singleton = 1 AND authority_sha256 = ?
                      AND prior_settlement_receipt_sha256 = ?
                      AND prior_execution_scope_sha256 = ?
                      AND prior_actual_cost_usd = '0.00564445'
                      AND incremental_cap_usd = '4.00'
                      AND cumulative_cap_usd = '4.00564445'
                      AND state = 'available' AND active_reservation_id IS NULL""",
                    (
                        additional_authority_sha256,
                        additional_prior_settlement_receipt_sha256,
                        additional_prior_execution_scope_sha256,
                    ),
                ).fetchone()
                if additional_grant is None:
                    raise DatabaseError("reference additional grant is unavailable")
                _validate_reference_additional_prior_lineage(connection)
            prior_scope_rows = connection.execute(
                """SELECT br.reservation_id, br.status, e.config_json,
                    rac.challenge_sha256, rac.approval_digest
                FROM budget_reservations AS br
                JOIN experiments AS e ON e.run_id = br.run_id
                LEFT JOIN reference_approval_challenges AS rac ON rac.run_id = br.run_id
                WHERE br.reference_execution_scope_sha256 = ?""",
                (execution_scope_sha256,),
            ).fetchall()
            for prior in prior_scope_rows:
                if prior["status"] in {
                    "submission_pending",
                    "submitted",
                    "settlement_pending",
                    "settled",
                    "failed",
                    "audit_blocked",
                }:
                    allowed_original = (
                        replacement is not None
                        and prior["reservation_id"] == replacement["original_reservation_id"]
                        and execution_scope_sha256 == replacement["original_execution_scope_sha256"]
                        and prior["status"] == "settled"
                    )
                    allowed_additional_history = additional_mode and prior["status"] in {
                        "settled",
                        "failed",
                    }
                    if not allowed_original and not allowed_additional_history:
                        raise DatabaseError("reference execution scope is permanently consumed")
                if prior["status"] == "released":
                    prior_config = json.loads(prior["config_json"])
                    prior_observation = prior_config["provider"]["observation_receipt_sha256"]
                    current_observation = parsed_config["provider"]["observation_receipt_sha256"]
                    if prior_observation == current_observation:
                        raise DatabaseError(
                            "released reference scope requires a fresh observation receipt"
                        )
                    if (
                        prior["challenge_sha256"] == challenge_sha256
                        or prior["approval_digest"] == approval_digest
                    ):
                        raise DatabaseError(
                            "released reference scope requires a new challenge and approval"
                        )
            phase_committed = _committed_reference_cost(connection)
            smoke_committed = _committed_provider_smoke_cost(connection)
            total_committed = phase_committed + smoke_committed
            if additional_mode:
                active = connection.execute(
                    """SELECT 1 FROM budget_reservations WHERE status IN (
                        'reserved', 'submission_pending', 'submitted',
                        'settlement_pending', 'audit_blocked'
                    ) LIMIT 1"""
                ).fetchone()
                if active is not None:
                    raise DatabaseError("reference additional reservation overlaps active work")
            original_slot_exists = connection.execute(
                "SELECT 1 FROM reference_authority_slots WHERE singleton = 1"
            ).fetchone()
            if (not replacement_mode and not additional_mode and original_slot_exists) or (
                (replacement_mode or additional_mode) and original_slot_exists is None
            ):
                raise DatabaseError("reference U8 authority slot is already consumed")
            if smoke_committed != REFERENCE_SETTLED_SMOKE_USD:
                raise DatabaseError(
                    "reference cumulative ledger does not contain the exact settled "
                    "provider smoke cost"
                )
            if not additional_mode and phase_committed + requested > phase_cap:
                raise DatabaseError("reference reservation exceeds phase cap")
            if total_committed + requested > total_cap:
                raise DatabaseError("reference reservation exceeds cumulative cap")
            registered = connection.execute(
                "SELECT config_sha256, config_json FROM experiment_configs WHERE experiment_id = ?",
                (experiment_id,),
            ).fetchone()
            if registered is None:
                cursor = connection.execute(
                    """INSERT INTO experiment_configs(experiment_id, config_sha256, config_json)
                    VALUES (?, ?, ?)""",
                    (experiment_id, config_sha256, config_json),
                )
            elif (
                registered["config_sha256"] != config_sha256
                or registered["config_json"] != config_json
            ):
                raise DatabaseError(
                    f"experiment_id is already bound to a different config: {experiment_id}"
                )
            attempt = connection.execute(
                "SELECT status FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None or attempt["status"] != "received":
                raise DatabaseError(f"attempt cannot be linked: {attempt_id}")
            connection.execute(
                """INSERT INTO experiments(
                    run_id, experiment_id, config_sha256, config_json, source_hashes_json,
                    runtime_json, hardware_json, phase, mode, status,
                    modal_cost_requested_usd, modal_cost_actual_usd, owner_id,
                    lease_expires_at, heartbeat_at, started_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, 1, 'modal_reference', 'created', ?, NULL, ?, ?, ?, ?
                )""",
                (
                    run_id,
                    experiment_id,
                    config_sha256,
                    config_json,
                    json.dumps(source_hashes, sort_keys=True, separators=(",", ":")),
                    json.dumps(runtime, sort_keys=True, separators=(",", ":")),
                    json.dumps(hardware, sort_keys=True, separators=(",", ":")),
                    requested_cost_usd,
                    owner_id,
                    lease_expires_at,
                    started_at,
                    started_at,
                ),
            )
            connection.execute(
                """INSERT INTO state_transitions(run_id, from_state, to_state)
                VALUES (?, NULL, 'created')""",
                (run_id,),
            )
            connection.execute(
                """UPDATE attempts SET status = 'linked', run_id = ?, ended_at = ?
                WHERE attempt_id = ? AND status = 'received'""",
                (run_id, started_at, attempt_id),
            )
            connection.execute(
                """INSERT INTO budget_reservations(
                    reservation_id, run_id, experiment_id, reference_execution_scope_sha256,
                    trust_override_sha256,
                    phase, status, requested_cost_usd, billing_authority_sha256,
                    authoritative_report_identity_sha256,
                    billing_completeness_delay_seconds,
                    idempotency_key, owner_id, lease_expires_at, heartbeat_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, 'reserved', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    reservation_id,
                    run_id,
                    experiment_id,
                    execution_scope_sha256,
                    parsed_config["provider"]["trust_override_sha256"],
                    requested_cost_usd,
                    parsed_config["provider"]["billing_authority_sha256"],
                    parsed_config["provider"]["authoritative_report_identity_sha256"],
                    parsed_config["provider"]["billing_completeness_delay_seconds"],
                    idempotency_key,
                    owner_id,
                    lease_expires_at,
                    started_at,
                    started_at,
                    started_at,
                ),
            )
            if additional_mode:
                cursor = connection.execute(
                    """UPDATE reference_additional_grants
                    SET active_reservation_id = ?, active_execution_scope_sha256 = ?,
                        reserved_at = ?
                    WHERE singleton = 1 AND state = 'available'
                      AND active_reservation_id IS NULL AND authority_sha256 = ?""",
                    (
                        reservation_id,
                        execution_scope_sha256,
                        started_at,
                        additional_authority_sha256,
                    ),
                )
                if cursor.rowcount != 1:
                    raise DatabaseError("reference additional grant reservation lost its race")
            cursor = connection.execute(
                """UPDATE reference_approval_challenges SET consumed_at = ?, run_id = ?
                WHERE challenge_sha256 = ? AND approval_digest = ? AND consumed_at IS NULL""",
                (started_at, run_id, challenge_sha256, approval_digest),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference approval could not be consumed atomically")

    def reference_additional_grant(self) -> dict[str, Any]:
        """Return the singleton final grant without exposing provider identity."""
        with self.connect_readonly() as connection:
            rows = connection.execute(
                "SELECT * FROM reference_additional_grants LIMIT 2"
            ).fetchall()
        if len(rows) != 1:
            raise DatabaseError("reference additional grant cardinality is invalid")
        return dict(rows[0])

    def release_reference_additional_reservation(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        reason: str,
        occurred_at: str,
    ) -> None:
        """Release a deterministic pre-boundary failure without consuming the grant."""
        occurred = _database_timestamp(occurred_at, "occurred_at")
        if not owner_id or not reason or len(reason.encode()) > 1_000:
            raise DatabaseError("reference additional release metadata is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT br.run_id, br.heartbeat_at
                FROM budget_reservations AS br
                JOIN reference_additional_grants AS rag
                  ON rag.active_reservation_id = br.reservation_id
                WHERE br.reservation_id = ? AND br.owner_id = ?
                  AND br.status = 'reserved' AND rag.singleton = 1
                  AND rag.state = 'available'""",
                (reservation_id, owner_id),
            ).fetchone()
            if row is None:
                raise DatabaseError("reference additional reservation is not releasable")
            if occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at"):
                raise DatabaseError("reference additional release time is backdated")
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'released', provider_actual_cost_usd = '0',
                    failure_reason = ?, heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = 'reserved'""",
                (reason, occurred_at, occurred_at, reservation_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference additional reservation release lost its race")
            cursor = connection.execute(
                """UPDATE reference_additional_grants
                SET active_reservation_id = NULL, active_execution_scope_sha256 = NULL,
                    reserved_at = NULL
                WHERE singleton = 1 AND state = 'available'
                  AND active_reservation_id = ?""",
                (reservation_id,),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference additional grant release lost its race")
            cursor = connection.execute(
                """UPDATE experiments SET status = 'failed', modal_cost_actual_usd = '0',
                    failure_reason = ?, ended_at = ?
                WHERE run_id = ? AND status = 'created'""",
                (reason, occurred_at, row["run_id"]),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference additional run release lost its race")
            connection.execute(
                """INSERT INTO state_transitions(
                    run_id, from_state, to_state, reason, occurred_at
                ) VALUES (?, 'created', 'failed', ?, ?)""",
                (row["run_id"], reason, occurred_at),
            )

    def mark_reference_additional_submission_pending(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        additional_authority_sha256: str,
        auth_receipt_bytes: bytes,
        authority_root: Path,
        occurred_at: str,
        additional_authority_path: Path = ADDITIONAL_AUTHORITY_PATH,
    ) -> None:
        """Consume the final grant atomically at the reservation-specific boundary."""
        occurred = _database_timestamp(occurred_at, "occurred_at")
        if not owner_id or additional_authority_sha256 != REFERENCE_ADDITIONAL_AUTHORITY_SHA256:
            raise DatabaseError("reference additional boundary authority is invalid")
        try:
            validated = validate_reference_additional_authority(
                authority_root, additional_authority_path
            )
        except ReferenceAuthorityError as exc:
            raise DatabaseError("reference additional authority file is invalid") from exc
        if validated != additional_authority_sha256:
            raise DatabaseError("reference additional authority digest does not match its files")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT br.reference_execution_scope_sha256, br.lease_expires_at,
                    br.heartbeat_at, rag.active_execution_scope_sha256
                FROM budget_reservations AS br
                JOIN reference_additional_grants AS rag
                  ON rag.active_reservation_id = br.reservation_id
                WHERE br.reservation_id = ? AND br.owner_id = ?
                  AND br.status = 'reserved' AND rag.singleton = 1
                  AND rag.authority_sha256 = ? AND rag.state = 'available'
                  AND rag.prior_settlement_receipt_sha256 = ?
                  AND rag.prior_execution_scope_sha256 = ?
                  AND rag.prior_actual_cost_usd = '0.00564445'""",
                (
                    reservation_id,
                    owner_id,
                    additional_authority_sha256,
                    REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256,
                    REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256,
                ),
            ).fetchone()
            if (
                row is None
                or row["reference_execution_scope_sha256"] != row["active_execution_scope_sha256"]
            ):
                raise DatabaseError("reference additional grant is not ready for provider contact")
            auth_receipt_sha256 = _validate_additional_provider_auth_receipt(
                auth_receipt_bytes,
                reservation_id=reservation_id,
                execution_scope_sha256=row["reference_execution_scope_sha256"],
                authority_sha256=additional_authority_sha256,
            )
            if occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at"):
                raise DatabaseError("reference additional provider-contact time is backdated")
            if occurred > _database_timestamp(row["lease_expires_at"], "stored lease_expires_at"):
                raise DatabaseError("reference additional reservation lease has expired")
            # The prior receipt remains immutable even after this reservation adds USD 4.00.
            prior = connection.execute(
                """SELECT status, provider_actual_cost_usd FROM budget_reservations
                WHERE settlement_identity = ? AND reference_execution_scope_sha256 = ?""",
                (
                    REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256,
                    REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256,
                ),
            ).fetchone()
            if (
                prior is None
                or prior["status"] not in {"settled", "failed"}
                or _database_actual_money(
                    prior["provider_actual_cost_usd"], "additional prior actual cost"
                )
                != REFERENCE_ADDITIONAL_PRIOR_SPEND_USD - REFERENCE_SETTLED_SMOKE_USD
                or _committed_provider_cost(connection) != REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD
            ):
                raise DatabaseError("reference additional cumulative reservation lineage drifted")
            cursor = connection.execute(
                """UPDATE reference_additional_grants SET state = 'consumed', consumed_at = ?,
                    consumed_auth_receipt_sha256 = ?
                WHERE singleton = 1 AND authority_sha256 = ? AND state = 'available'
                  AND active_reservation_id = ? AND consumed_at IS NULL""",
                (
                    occurred_at,
                    auth_receipt_sha256,
                    additional_authority_sha256,
                    reservation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference additional grant was already consumed")
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'submission_pending', heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = 'reserved'""",
                (occurred_at, occurred_at, reservation_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference additional boundary transition failed")

    def mark_reference_submission_pending(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        standing_authority_sha256: str,
        bootstrap_authority_sha256: str,
        authority_root: Path,
        occurred_at: str,
        authority_path: Path = AUTHORITY_PATH,
        bootstrap_authority_path: Path = BOOTSTRAP_AUTHORITY_PATH,
    ) -> None:
        """Consume the one U8 slot immediately before any provider import or contact."""
        occurred = _database_timestamp(occurred_at, "occurred_at")
        if (
            not owner_id
            or standing_authority_sha256 != REFERENCE_AUTHORITY_SHA256
            or bootstrap_authority_sha256 != REFERENCE_BOOTSTRAP_AUTHORITY_SHA256
        ):
            raise DatabaseError("reference submission boundary authority is invalid")
        try:
            validated_authority_sha256 = validate_reference_authority(
                authority_root, authority_path
            )
            validated_bootstrap_sha256 = validate_reference_bootstrap_authority(
                authority_root, bootstrap_authority_path
            )
        except ReferenceAuthorityError as exc:
            raise DatabaseError(
                "reference standing or bootstrap authority files are invalid"
            ) from exc
        if validated_authority_sha256 != standing_authority_sha256:
            raise DatabaseError("reference standing authority digest does not match its files")
        if validated_bootstrap_sha256 != bootstrap_authority_sha256:
            raise DatabaseError("reference bootstrap authority digest does not match its files")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT reference_execution_scope_sha256, lease_expires_at, heartbeat_at
                FROM budget_reservations
                WHERE reservation_id = ? AND owner_id = ? AND status = 'reserved'""",
                (reservation_id, owner_id),
            ).fetchone()
            if row is None or row["reference_execution_scope_sha256"] is None:
                raise DatabaseError("reference reservation is not ready for provider contact")
            if occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at"):
                raise DatabaseError("reference provider-contact time is backdated")
            if occurred > _database_timestamp(row["lease_expires_at"], "stored lease_expires_at"):
                raise DatabaseError("reference reservation lease has expired")
            if connection.execute(
                "SELECT 1 FROM reference_authority_slots WHERE singleton = 1"
            ).fetchone():
                raise DatabaseError("reference U8 authority slot is already consumed")
            connection.execute(
                """INSERT INTO reference_authority_slots(
                    singleton, authority_sha256, state,
                    execution_scope_sha256, consumed_at
                ) VALUES (1, ?, 'consumed', ?, ?)""",
                (
                    standing_authority_sha256,
                    row["reference_execution_scope_sha256"],
                    occurred_at,
                ),
            )
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'submission_pending', heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = 'reserved'""",
                (occurred_at, occurred_at, reservation_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference submission boundary transition failed")

    def register_reference_challenge(
        self, *, challenge_sha256: str, packet_sha256: str, created_at: str
    ) -> None:
        _database_sha256(challenge_sha256, "challenge_sha256")
        _database_sha256(packet_sha256, "packet_sha256")
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO reference_approval_challenges(
                    challenge_sha256, packet_sha256, created_at
                ) VALUES (?, ?, ?)""",
                (challenge_sha256, packet_sha256, created_at),
            )

    def attach_reference_approval(
        self, *, challenge_sha256: str, approval_digest: str, expires_at: str
    ) -> None:
        _database_sha256(challenge_sha256, "challenge_sha256")
        _database_sha256(approval_digest, "approval_digest")
        _database_timestamp(expires_at, "expires_at")
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE reference_approval_challenges
                SET approval_digest = ?, expires_at = ?
                WHERE challenge_sha256 = ? AND approval_digest IS NULL AND consumed_at IS NULL""",
                (approval_digest, expires_at, challenge_sha256),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference approval cannot be attached")

    def mark_reference_provider_prepared(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        provider_image_identity: str,
        app_identity: str,
        occurred_at: str,
        lease_expires_at: str,
    ) -> None:
        """Persist the first provider identities before the function can be spawned."""
        occurred = _database_timestamp(occurred_at, "occurred_at")
        lease_expiry = _database_timestamp(lease_expires_at, "lease_expires_at")
        if (
            not owner_id
            or not _controller_identifier(provider_image_identity, "provider_image_identity")
            or not _controller_identifier(app_identity, "app_identity")
            or lease_expiry <= occurred
        ):
            raise DatabaseError("provider preparation identity or lease is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT heartbeat_at, lease_expires_at,
                    reference_execution_scope_sha256, app_identity
                FROM budget_reservations
                WHERE reservation_id = ? AND owner_id = ? AND status = 'submission_pending'""",
                (reservation_id, owner_id),
            ).fetchone()
            if row is not None and not _reference_boundary_consumed(
                connection,
                reservation_id=reservation_id,
                execution_scope_sha256=row["reference_execution_scope_sha256"],
            ):
                raise DatabaseError("reference provider-contact boundary was not consumed")
            if (
                row is None
                or row["app_identity"] not in (None, app_identity)
                or occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at")
                or occurred
                > _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
            ):
                raise DatabaseError("reference provider preparation is not current")
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET provider_image_identity = ?, app_identity = ?, heartbeat_at = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = 'submission_pending'""",
                (
                    provider_image_identity,
                    app_identity,
                    occurred_at,
                    lease_expires_at,
                    occurred_at,
                    reservation_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference provider preparation transition failed")

    def mark_reference_app_identity(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        app_identity: str,
        occurred_at: str,
        lease_expires_at: str,
    ) -> None:
        """Persist the provider app identity immediately on app-context entry."""
        occurred = _database_timestamp(occurred_at, "occurred_at")
        lease_expiry = _database_timestamp(lease_expires_at, "lease_expires_at")
        if (
            not owner_id
            or not _controller_identifier(app_identity, "app_identity")
            or lease_expiry <= occurred
        ):
            raise DatabaseError("provider app identity or lease is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT heartbeat_at, lease_expires_at,
                    reference_execution_scope_sha256, app_identity
                FROM budget_reservations
                WHERE reservation_id = ? AND owner_id = ? AND status = 'submission_pending'""",
                (reservation_id, owner_id),
            ).fetchone()
            if row is not None and not _reference_boundary_consumed(
                connection,
                reservation_id=reservation_id,
                execution_scope_sha256=row["reference_execution_scope_sha256"],
            ):
                raise DatabaseError("reference provider-contact boundary was not consumed")
            if (
                row is None
                or row["app_identity"] is not None
                or occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at")
                or occurred
                > _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
            ):
                raise DatabaseError("reference app identity is not current")
            cursor = connection.execute(
                """UPDATE budget_reservations SET app_identity = ?, heartbeat_at = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = 'submission_pending'
                  AND app_identity IS NULL""",
                (
                    app_identity,
                    occurred_at,
                    lease_expires_at,
                    occurred_at,
                    reservation_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference app identity persistence lost its race")

    def mark_reservation_submitted(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        provider_job_id: str,
        app_identity: str,
        occurred_at: str,
        lease_expires_at: str,
    ) -> None:
        occurred = _database_timestamp(occurred_at, "occurred_at")
        lease_expiry = _database_timestamp(lease_expires_at, "lease_expires_at")
        if not owner_id or not provider_job_id or not app_identity:
            raise DatabaseError("submitted reservation requires provider identity")
        if lease_expiry <= occurred:
            raise DatabaseError("submitted reservation lease must expire in the future")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT lease_expires_at, heartbeat_at, reference_execution_scope_sha256,
                    provider_image_identity, app_identity
                FROM budget_reservations
                WHERE reservation_id = ?""",
                (reservation_id,),
            ).fetchone()
            if row is not None and occurred > _database_timestamp(
                row["lease_expires_at"], "stored lease_expires_at"
            ):
                raise DatabaseError("submitted reservation lease has expired")
            if (
                row is not None
                and row["reference_execution_scope_sha256"] is not None
                and not _reference_boundary_consumed(
                    connection,
                    reservation_id=reservation_id,
                    execution_scope_sha256=row["reference_execution_scope_sha256"],
                )
            ):
                raise DatabaseError("reference provider-contact boundary was not consumed")
            if (
                row is None
                or occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at")
                or lease_expiry
                <= _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
                or (
                    row["reference_execution_scope_sha256"] is not None
                    and row["provider_image_identity"] is None
                )
                or row["app_identity"] != app_identity
            ):
                raise DatabaseError("submitted reservation lease must advance")
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'submitted', provider_job_id = ?, app_identity = ?,
                    submitted_at = ?, heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'submission_pending' AND owner_id = ?""",
                (
                    provider_job_id,
                    app_identity,
                    occurred_at,
                    occurred_at,
                    lease_expires_at,
                    occurred_at,
                    reservation_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"reservation cannot be submitted: {reservation_id}")

    def mark_settlement_pending(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        occurred_at: str,
        provider_terminal_at: str,
        lease_expires_at: str,
    ) -> None:
        occurred = _database_timestamp(occurred_at, "occurred_at")
        terminal = _database_timestamp(provider_terminal_at, "provider_terminal_at")
        lease_expiry = _database_timestamp(lease_expires_at, "lease_expires_at")
        if lease_expiry <= occurred:
            raise DatabaseError("settlement lease must expire after the transition")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT lease_expires_at, heartbeat_at, submitted_at,
                    reference_execution_scope_sha256
                FROM budget_reservations WHERE reservation_id = ?""",
                (reservation_id,),
            ).fetchone()
            if row is not None and row["submitted_at"] is not None:
                submitted = _database_timestamp(row["submitted_at"], "submitted_at")
                if terminal < submitted or terminal > occurred:
                    raise DatabaseError("provider terminal time is outside the transition window")
            if (
                row is None
                or not _reference_boundary_consumed(
                    connection,
                    reservation_id=reservation_id,
                    execution_scope_sha256=row["reference_execution_scope_sha256"],
                )
                or row["submitted_at"] is None
                or occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at")
                or occurred
                > _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
                or lease_expiry
                <= _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
            ):
                raise DatabaseError("settlement lease must advance")
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'settlement_pending', settlement_pending_at = ?,
                    heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'submitted' AND owner_id = ?""",
                (
                    provider_terminal_at,
                    occurred_at,
                    lease_expires_at,
                    occurred_at,
                    reservation_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"reservation cannot await settlement: {reservation_id}")

    def mark_reference_audit_blocked(
        self, reservation_id: str, *, owner_id: str, reason: str, occurred_at: str
    ) -> None:
        """Make every post-boundary uncertainty durable and non-replayable."""
        _database_timestamp(occurred_at, "occurred_at")
        safe_reason = _controller_text(reason, "audit reason", maximum=256)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT reference_execution_scope_sha256 FROM budget_reservations
                WHERE reservation_id = ? AND owner_id = ?
                  AND status IN ('submission_pending', 'submitted', 'settlement_pending')""",
                (reservation_id, owner_id),
            ).fetchone()
            if row is None or not _reference_boundary_consumed(
                connection,
                reservation_id=reservation_id,
                execution_scope_sha256=row["reference_execution_scope_sha256"],
            ):
                raise DatabaseError("reference provider-contact boundary was not consumed")
            cursor = connection.execute(
                """UPDATE budget_reservations SET status = 'audit_blocked',
                    failure_reason = ?, heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ?
                  AND status IN ('submission_pending', 'submitted', 'settlement_pending')""",
                (safe_reason, occurred_at, occurred_at, reservation_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference audit block lost reservation ownership")

    def renew_reservation_lease(
        self,
        reservation_id: str,
        *,
        owner_id: str,
        occurred_at: str,
        lease_expires_at: str,
    ) -> None:
        occurred = _database_timestamp(occurred_at, "occurred_at")
        lease_expiry = _database_timestamp(lease_expires_at, "lease_expires_at")
        if lease_expiry <= occurred:
            raise DatabaseError("renewed reservation lease must expire in the future")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT lease_expires_at, heartbeat_at FROM budget_reservations
                WHERE reservation_id = ? AND owner_id = ?
                  AND status IN (
                    'reserved', 'submission_pending', 'submitted', 'settlement_pending'
                  )""",
                (reservation_id, owner_id),
            ).fetchone()
            if row is not None and occurred > _database_timestamp(
                row["lease_expires_at"], "stored lease_expires_at"
            ):
                raise DatabaseError(f"reservation lease has expired: {reservation_id}")
            if (
                row is None
                or occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at")
                or lease_expiry
                <= _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
            ):
                raise DatabaseError(f"reservation lease cannot renew: {reservation_id}")
            connection.execute(
                """UPDATE budget_reservations SET heartbeat_at = ?, lease_expires_at = ?,
                    updated_at = ? WHERE reservation_id = ? AND owner_id = ?
                    AND status IN (
                        'reserved', 'submission_pending', 'submitted', 'settlement_pending'
                    )""",
                (occurred_at, lease_expires_at, occurred_at, reservation_id, owner_id),
            )

    def reconcile_reference_audit_billing(
        self,
        reservation_id: str,
        *,
        billing_report_json: str,
        billing_report_sha256: str,
        occurred_at: str,
    ) -> None:
        """Bind an audit-blocked provider boundary to an authoritative billing window."""
        report, _ = _reference_billing_report(billing_report_json, billing_report_sha256)
        occurred = _database_timestamp(occurred_at, "occurred_at")
        covered = _database_timestamp(report["covered_through"], "covered_through")
        if covered > occurred:
            raise DatabaseError("authoritative billing coverage is in the future")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT br.provider_job_id, br.app_identity, br.billing_authority_sha256,
                    br.authoritative_report_identity_sha256, br.submitted_at,
                    br.heartbeat_at, ras.consumed_at
                FROM budget_reservations AS br
                JOIN reference_authority_slots AS ras
                  ON ras.execution_scope_sha256 = br.reference_execution_scope_sha256
                WHERE br.reservation_id = ? AND br.status = 'audit_blocked'""",
                (reservation_id,),
            ).fetchone()
            provider_identity = (
                None if row is None else row["provider_job_id"] or row["app_identity"]
            )
            if (
                row is None
                or provider_identity is None
                or report["provider_job_id"] != provider_identity
                or report["billing_authority_sha256"] != row["billing_authority_sha256"]
                or report["authoritative_report_identity_sha256"]
                != row["authoritative_report_identity_sha256"]
            ):
                raise DatabaseError("audit billing evidence does not match provider lineage")
            heartbeat = _database_timestamp(row["heartbeat_at"], "stored heartbeat_at")
            boundary = _database_timestamp(row["consumed_at"], "provider boundary time")
            if row["submitted_at"] is not None:
                boundary = max(
                    boundary,
                    _database_timestamp(row["submitted_at"], "submitted_at"),
                )
            if occurred < heartbeat:
                raise DatabaseError("audit billing reconciliation time is backdated")
            if covered < boundary + timedelta(seconds=2700):
                raise DatabaseError("authoritative billing does not cover the full action window")
            cursor = connection.execute(
                """UPDATE budget_reservations SET settlement_pending_at = ?,
                    provider_job_id = COALESCE(provider_job_id, ?),
                    submitted_at = COALESCE(submitted_at, ?), heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'audit_blocked'
                  AND settlement_pending_at IS NULL""",
                (
                    report["covered_through"],
                    report["provider_job_id"],
                    row["consumed_at"],
                    occurred_at,
                    occurred_at,
                    reservation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("audit billing window was already reconciled")

    def settle_reservation(
        self,
        reservation_id: str,
        *,
        actual_cost_usd: str,
        billing_authority_sha256: str,
        authoritative_report_identity_sha256: str,
        billing_report_json: str,
        billing_report_sha256: str,
        occurred_at: str,
    ) -> None:
        actual = _database_actual_money(actual_cost_usd, "actual_cost_usd")
        _database_sha256(billing_authority_sha256, "billing_authority_sha256")
        _database_sha256(
            authoritative_report_identity_sha256,
            "authoritative_report_identity_sha256",
        )
        report, report_actual = _reference_billing_report(
            billing_report_json, billing_report_sha256
        )
        if report_actual != actual:
            raise DatabaseError("billing report receipt cost mismatch")
        occurred = _database_timestamp(occurred_at, "occurred_at")
        budget_failure = False
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT run_id, requested_cost_usd, status, billing_authority_sha256,
                    authoritative_report_identity_sha256,
                    billing_completeness_delay_seconds, settlement_pending_at,
                    provider_job_id, app_identity
                FROM budget_reservations
                WHERE reservation_id = ?""",
                (reservation_id,),
            ).fetchone()
            if (
                row is None
                or row["status"] not in {"settlement_pending", "audit_blocked"}
                or row["settlement_pending_at"] is None
            ):
                raise DatabaseError(f"reservation cannot settle: {reservation_id}")
            if (
                row["billing_authority_sha256"] != billing_authority_sha256
                or row["authoritative_report_identity_sha256"]
                != authoritative_report_identity_sha256
                or report["billing_authority_sha256"] != billing_authority_sha256
                or report["authoritative_report_identity_sha256"]
                != authoritative_report_identity_sha256
                or report["provider_job_id"] != (row["provider_job_id"] or row["app_identity"])
            ):
                raise DatabaseError("settlement billing authority or report identity mismatch")
            terminal_at = _database_timestamp(row["settlement_pending_at"], "settlement_pending_at")
            complete_at = terminal_at + timedelta(seconds=row["billing_completeness_delay_seconds"])
            if (
                occurred < complete_at
                or _database_timestamp(report["covered_through"], "covered_through") < terminal_at
            ):
                raise DatabaseError("authoritative provider billing report is not yet complete")
            settlement_identity = billing_report_sha256
            if actual > _database_money(row["requested_cost_usd"], "requested_cost_usd"):
                reason = (
                    "authoritative provider actual cost exceeds the USD 4.00 local reservation; "
                    "budget failure"
                )
                cursor = connection.execute(
                    """UPDATE budget_reservations SET status = 'failed',
                        provider_actual_cost_usd = ?, settlement_identity = ?, failure_reason = ?,
                        heartbeat_at = ?, updated_at = ? WHERE reservation_id = ?
                        AND status IN ('submitted', 'settlement_pending', 'audit_blocked')""",
                    (
                        actual_cost_usd,
                        settlement_identity,
                        reason,
                        occurred_at,
                        occurred_at,
                        reservation_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise DatabaseError(f"reservation cannot settle: {reservation_id}")
                run = connection.execute(
                    "SELECT status FROM experiments WHERE run_id = ?", (row["run_id"],)
                ).fetchone()
                if run is None:
                    raise DatabaseError(f"reservation run is missing: {reservation_id}")
                connection.execute(
                    """UPDATE experiments SET status = 'failed', modal_cost_actual_usd = ?,
                        failure_reason = ?, ended_at = ? WHERE run_id = ?""",
                    (actual_cost_usd, reason, occurred_at, row["run_id"]),
                )
                connection.execute(
                    """INSERT INTO state_transitions(
                        run_id, from_state, to_state, reason, occurred_at
                    ) VALUES (?, ?, 'failed', ?, ?)""",
                    (row["run_id"], run["status"], reason, occurred_at),
                )
                budget_failure = True
            else:
                cursor = connection.execute(
                    """UPDATE budget_reservations SET status = 'settled',
                        provider_actual_cost_usd = ?, settlement_identity = ?,
                        failure_reason = NULL, heartbeat_at = ?, updated_at = ?
                        WHERE reservation_id = ?
                        AND status IN ('submitted', 'settlement_pending', 'audit_blocked')""",
                    (
                        actual_cost_usd,
                        settlement_identity,
                        occurred_at,
                        occurred_at,
                        reservation_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise DatabaseError(f"reservation cannot settle: {reservation_id}")
                connection.execute(
                    """UPDATE experiments SET modal_cost_actual_usd = ?, failure_reason = NULL
                    WHERE run_id = ?""",
                    (actual_cost_usd, row["run_id"]),
                )
        if budget_failure:
            raise DatabaseError(
                "authoritative provider cost was recorded as a terminal budget failure"
            )

    def settle_reference_preidentity_zero(
        self,
        receipt_bytes: bytes,
        report_bytes: bytes,
        *,
        pre_auth_receipt_bytes: bytes,
        post_auth_receipt_bytes: bytes,
        billing_authority_bytes: bytes,
        authority_root: Path,
        occurred_at: str,
        recovery_authority_path: Path = RECOVERY_AUTHORITY_PATH,
        reconciliation_authority_path: Path = WORKSPACE_RECONCILIATION_AUTHORITY_PATH,
    ) -> str:
        """Atomically settle the sole identity-less AuthError and mint one child entitlement."""
        self.initialize()
        occurred = _database_timestamp(occurred_at, "occurred_at")
        try:
            selector = json.loads(receipt_bytes)
            reservation_id = selector["reservation_id"]
        except (TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
            raise DatabaseError("pre-identity receipt selector is invalid") from exc
        if not isinstance(reservation_id, str):
            raise DatabaseError("pre-identity receipt selector is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT br.run_id, br.reference_execution_scope_sha256,
                    br.billing_authority_sha256,
                    br.authoritative_report_identity_sha256,
                    br.billing_completeness_delay_seconds, br.failure_reason,
                    br.provider_job_id, br.app_identity, br.provider_image_identity,
                    br.submitted_at, br.settlement_pending_at, br.settlement_mode,
                    br.heartbeat_at, br.updated_at, e.status AS run_status, e.config_json,
                    ras.consumed_at, ras.authority_sha256 AS original_authority_sha256
                FROM budget_reservations AS br
                JOIN experiments AS e ON e.run_id = br.run_id
                JOIN reference_authority_slots AS ras
                  ON ras.execution_scope_sha256 = br.reference_execution_scope_sha256
                WHERE br.reservation_id = ? AND br.status = 'audit_blocked'""",
                (reservation_id,),
            ).fetchone()
            if row is None:
                raise DatabaseError("pre-identity reservation is not uniquely audit-blocked")
            try:
                validated_recovery = validate_reference_recovery_authority(
                    authority_root, recovery_authority_path
                )
                reconciliation = validate_workspace_scope_reconciliation_authority(
                    authority_root, reconciliation_authority_path
                )
                config = json.loads(row["config_json"])
                provider = config["provider"]
                workspace_scope = provider["workspace_scope_sha256"]
                authority = json.loads(billing_authority_bytes)
                billing_method = authority["attribution_method_sha256"]
            except (ReferenceAuthorityError, TypeError, KeyError, json.JSONDecodeError) as exc:
                raise DatabaseError("pre-identity authority lineage is invalid") from exc
            if (
                validated_recovery != REFERENCE_RECOVERY_AUTHORITY_SHA256
                or row["original_authority_sha256"] != REFERENCE_AUTHORITY_SHA256
                or sha256_json(reconciliation)
                != REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
                or reconciliation["original_workspace_scope_sha256"] != workspace_scope
                or reconciliation["original_reservation_id"] != reservation_id
                or reconciliation["original_execution_scope_sha256"]
                != row["reference_execution_scope_sha256"]
                or reconciliation["billing_authority_sha256"] != row["billing_authority_sha256"]
                or hashlib.sha256(billing_authority_bytes).hexdigest()
                != row["billing_authority_sha256"]
                or authority.get("authoritative_report_identity_sha256")
                != row["authoritative_report_identity_sha256"]
                or authority.get("billing_completeness_delay_seconds")
                != row["billing_completeness_delay_seconds"]
            ):
                raise DatabaseError("pre-identity authority lineage drift")
            if any(
                row[field] is not None
                for field in (
                    "provider_job_id",
                    "app_identity",
                    "provider_image_identity",
                    "submitted_at",
                    "settlement_pending_at",
                    "settlement_mode",
                )
            ):
                raise DatabaseError("pre-identity settlement rejects provider or sentinel identity")
            failure_reason = row["failure_reason"]
            if failure_reason != "provider boundary uncertainty: AuthError":
                raise DatabaseError("pre-identity reservation failure is not the exact AuthError")
            if row["run_status"] == "completed":
                raise DatabaseError("completed reference run cannot be pre-identity settled")
            consumed_at = _database_timestamp(row["consumed_at"], "original consumed_at")
            latest_boundary = max(
                consumed_at,
                _database_timestamp(row["heartbeat_at"], "stored heartbeat_at"),
                _database_timestamp(row["updated_at"], "stored updated_at"),
            )
            try:
                evidence = validate_workspace_zero_settlement_evidence(
                    receipt_bytes,
                    report_bytes,
                    pre_auth_receipt_bytes=pre_auth_receipt_bytes,
                    post_auth_receipt_bytes=post_auth_receipt_bytes,
                    expected_recovery_authority_sha256=validated_recovery,
                    expected_original_workspace_scope_sha256=workspace_scope,
                    expected_authenticated_workspace_identity_sha256=reconciliation[
                        "authenticated_workspace_identity_sha256"
                    ],
                    expected_workspace_reconciliation_authority_sha256=(
                        REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256
                    ),
                    expected_billing_authority_sha256=row["billing_authority_sha256"],
                    expected_billing_method_sha256=billing_method,
                    expected_report_identity_sha256=row["authoritative_report_identity_sha256"],
                    expected_reservation_id=reservation_id,
                    expected_execution_scope_sha256=row["reference_execution_scope_sha256"],
                    latest_durable_boundary=latest_boundary,
                    validated_at=occurred,
                    maximum_action_seconds=int(REFERENCE_RESOURCES["timeout_seconds"]),
                    expected_completeness_delay_seconds=row["billing_completeness_delay_seconds"],
                )
            except ReferenceSettlementError as exc:
                raise DatabaseError("pre-identity evidence validation failed") from exc
            if occurred < evidence.acquired_at:
                raise DatabaseError("pre-identity settlement time is backdated")
            entitlement_sha256 = sha256_json(
                {
                    "kind": "reference_u8_replacement_entitlement",
                    "original_execution_scope_sha256": evidence.execution_scope_sha256,
                    "original_reservation_id": evidence.reservation_id,
                    "recovery_authority_sha256": evidence.recovery_authority_sha256,
                    "settlement_sha256": evidence.receipt_sha256,
                    "workspace_reconciliation_authority_sha256": (
                        evidence.workspace_reconciliation_authority_sha256
                    ),
                }
            )
            if connection.execute(
                "SELECT 1 FROM reference_preidentity_settlements LIMIT 1"
            ).fetchone():
                raise DatabaseError("pre-identity settlement authority is already consumed")
            if connection.execute(
                "SELECT 1 FROM reference_workspace_scope_reconciliations LIMIT 1"
            ).fetchone():
                raise DatabaseError("workspace reconciliation authority is already consumed")
            connection.execute(
                """INSERT INTO reference_workspace_scope_reconciliations(
                    authority_sha256, original_workspace_scope_sha256,
                    authenticated_workspace_identity_sha256, original_reservation_id,
                    original_execution_scope_sha256, billing_authority_sha256,
                    statement_sha256, approved_base_commit, replacement_action,
                    maximum_mapping_uses, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                (
                    evidence.workspace_reconciliation_authority_sha256,
                    evidence.original_workspace_scope_sha256,
                    evidence.authenticated_workspace_identity_sha256,
                    evidence.reservation_id,
                    evidence.execution_scope_sha256,
                    evidence.billing_authority_sha256,
                    reconciliation["statement_sha256"],
                    reconciliation["approved_base_commit"],
                    reconciliation["replacement_action"],
                    occurred_at,
                ),
            )
            connection.execute(
                """INSERT INTO reference_preidentity_settlements(
                    settlement_sha256, reservation_id, recovery_authority_sha256,
                    original_workspace_scope_sha256,
                    authenticated_workspace_identity_sha256,
                    workspace_reconciliation_authority_sha256, auth_binding_sha256,
                    pre_auth_receipt_sha256, post_auth_receipt_sha256,
                    billing_authority_sha256,
                    billing_method_sha256, authoritative_report_identity_sha256,
                    original_execution_scope_sha256, failure_code, query_start, query_end,
                    acquired_at, completeness_delay_seconds, actual_cost_usd,
                    report_sha256, report_size_bytes, row_count, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'auth_before_provider_identity',
                    ?, ?, ?, ?, '0', ?, ?, 0, ?)""",
                (
                    evidence.receipt_sha256,
                    evidence.reservation_id,
                    evidence.recovery_authority_sha256,
                    evidence.original_workspace_scope_sha256,
                    evidence.authenticated_workspace_identity_sha256,
                    evidence.workspace_reconciliation_authority_sha256,
                    evidence.auth_binding_sha256,
                    evidence.pre_auth_receipt_sha256,
                    evidence.post_auth_receipt_sha256,
                    evidence.billing_authority_sha256,
                    evidence.billing_method_sha256,
                    evidence.report_identity_sha256,
                    evidence.execution_scope_sha256,
                    evidence.query_start.isoformat(),
                    evidence.query_end.isoformat(),
                    evidence.acquired_at.isoformat(),
                    evidence.completeness_delay_seconds,
                    evidence.report_sha256,
                    evidence.report_size_bytes,
                    occurred_at,
                ),
            )
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'settled', provider_actual_cost_usd = '0',
                    settlement_identity = ?, settlement_mode = 'workspace_zero_preidentity',
                    heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'audit_blocked'
                  AND provider_job_id IS NULL AND app_identity IS NULL
                  AND submitted_at IS NULL AND settlement_pending_at IS NULL""",
                (
                    evidence.receipt_sha256,
                    occurred_at,
                    occurred_at,
                    evidence.reservation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("pre-identity reservation settlement lost its compare-and-set")
            if row["run_status"] != "failed":
                connection.execute(
                    """UPDATE experiments SET status = 'failed', modal_cost_actual_usd = '0',
                        failure_reason = ?, ended_at = ? WHERE run_id = ?
                        AND status NOT IN ('completed', 'failed')""",
                    (failure_reason, occurred_at, row["run_id"]),
                )
                connection.execute(
                    """INSERT INTO state_transitions(
                        run_id, from_state, to_state, reason, occurred_at
                    ) VALUES (?, ?, 'failed', ?, ?)""",
                    (row["run_id"], row["run_status"], failure_reason, occurred_at),
                )
            else:
                connection.execute(
                    """UPDATE experiments SET modal_cost_actual_usd = '0'
                    WHERE run_id = ?""",
                    (row["run_id"],),
                )
            connection.execute(
                """INSERT INTO reference_replacement_entitlements(
                    entitlement_sha256, recovery_authority_sha256,
                    workspace_reconciliation_authority_sha256,
                    original_reservation_id, original_execution_scope_sha256,
                    settlement_sha256, state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'available', ?)""",
                (
                    entitlement_sha256,
                    evidence.recovery_authority_sha256,
                    evidence.workspace_reconciliation_authority_sha256,
                    evidence.reservation_id,
                    evidence.execution_scope_sha256,
                    evidence.receipt_sha256,
                    occurred_at,
                ),
            )
        return entitlement_sha256

    def settle_reference_replacement_billing(
        self,
        receipt_bytes: bytes,
        app_evidence_bytes: bytes,
        filtered_report_bytes: bytes,
        *,
        pre_auth_receipt_bytes: bytes,
        post_auth_receipt_bytes: bytes,
        billing_authority_bytes: bytes,
        occurred_at: str,
    ) -> str:
        """Atomically settle the consumed replacement from app-attributed billing."""
        from lowbit_lab.reference_replacement_settlement import (
            ReplacementSettlementError,
            validate_replacement_settlement,
        )

        self.initialize()
        occurred = _database_timestamp(occurred_at, "occurred_at")
        try:
            selector = json.loads(receipt_bytes)
            reservation_id = selector["reservation_id"]
            authority = json.loads(billing_authority_bytes)
        except (TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
            raise DatabaseError("replacement settlement selector is invalid") from exc
        if not isinstance(reservation_id, str) or not isinstance(authority, dict):
            raise DatabaseError("replacement settlement selector is invalid")
        if (
            set(authority)
            != {
                "schema_version",
                "kind",
                "provider",
                "environment_scope_sha256",
                "attribution_method_sha256",
                "authoritative_report_identity_sha256",
                "billing_completeness_delay_seconds",
            }
            or authority.get("schema_version") != 2
            or authority.get("kind") != "provider_billing_authority_contract"
            or authority.get("provider") != "modal"
        ):
            raise DatabaseError("replacement billing authority is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT br.run_id, br.reference_execution_scope_sha256,
                    br.requested_cost_usd, br.status, br.failure_reason,
                    br.provider_job_id, br.app_identity, br.submitted_at,
                    br.settlement_pending_at, br.billing_authority_sha256,
                    br.authoritative_report_identity_sha256,
                    br.billing_completeness_delay_seconds, br.heartbeat_at,
                    e.status AS run_status, e.config_json, rre.entitlement_sha256, rre.consumed_at,
                    rps.auth_binding_sha256,
                    rws.original_workspace_scope_sha256,
                    rws.authenticated_workspace_identity_sha256,
                    rws.authority_sha256 AS reconciliation_authority_sha256
                FROM budget_reservations AS br
                JOIN experiments AS e ON e.run_id = br.run_id
                JOIN reference_replacement_entitlements AS rre
                  ON rre.replacement_reservation_id = br.reservation_id
                JOIN reference_workspace_scope_reconciliations AS rws
                  ON rws.authority_sha256 = rre.workspace_reconciliation_authority_sha256
                JOIN reference_preidentity_settlements AS rps
                  ON rps.settlement_sha256 = rre.settlement_sha256
                WHERE br.reservation_id = ? AND rre.state = 'consumed'""",
                (reservation_id,),
            ).fetchone()
            if (
                row is None
                or row["status"] != "audit_blocked"
                or row["failure_reason"] != REFERENCE_REPLACEMENT_AUDIT_REASON
                or row["provider_job_id"] is not None
                or row["app_identity"] is not None
                or row["submitted_at"] is not None
                or row["settlement_pending_at"] is not None
                or hashlib.sha256(billing_authority_bytes).hexdigest()
                != row["billing_authority_sha256"]
                or authority.get("authoritative_report_identity_sha256")
                != row["authoritative_report_identity_sha256"]
                or authority.get("billing_completeness_delay_seconds")
                != row["billing_completeness_delay_seconds"]
            ):
                raise DatabaseError("replacement reservation is not settlement-eligible")
            try:
                config = json.loads(row["config_json"])
                environment_scope_sha256 = config["provider"]["environment_scope_sha256"]
                if environment_scope_sha256 != authority["environment_scope_sha256"]:
                    raise DatabaseError("replacement billing environment scope lineage drift")
                evidence = validate_replacement_settlement(
                    receipt_bytes,
                    app_evidence_bytes,
                    filtered_report_bytes,
                    pre_auth_receipt_bytes=pre_auth_receipt_bytes,
                    post_auth_receipt_bytes=post_auth_receipt_bytes,
                    expected_reservation_id=reservation_id,
                    expected_execution_scope_sha256=row["reference_execution_scope_sha256"],
                    expected_entitlement_sha256=row["entitlement_sha256"],
                    expected_environment_scope_sha256=environment_scope_sha256,
                    expected_original_workspace_scope_sha256=row["original_workspace_scope_sha256"],
                    expected_workspace_identity_sha256=row[
                        "authenticated_workspace_identity_sha256"
                    ],
                    expected_reconciliation_authority_sha256=row["reconciliation_authority_sha256"],
                    expected_auth_binding_sha256=row["auth_binding_sha256"],
                    expected_billing_authority_sha256=row["billing_authority_sha256"],
                    expected_billing_method_sha256=authority["attribution_method_sha256"],
                    expected_report_identity_sha256=row["authoritative_report_identity_sha256"],
                    action_consumed_at=_database_timestamp(
                        row["consumed_at"], "replacement consumed_at"
                    ),
                    latest_boundary_at=_database_timestamp(
                        row["heartbeat_at"], "replacement heartbeat_at"
                    ),
                    maximum_action_seconds=int(REFERENCE_RESOURCES["timeout_seconds"]),
                    expected_completeness_delay_seconds=row["billing_completeness_delay_seconds"],
                    validated_at=occurred,
                )
            except (KeyError, TypeError, json.JSONDecodeError, ReplacementSettlementError) as exc:
                raise DatabaseError("replacement billing evidence validation failed") from exc
            if row["run_status"] != "created":
                raise DatabaseError("replacement run state is not settlement-eligible")
            if occurred < evidence.acquired_at:
                raise DatabaseError("replacement settlement time is backdated")
            actual = _database_actual_money(evidence.actual_cost_usd, "actual_cost_usd")
            over_cap = actual > _database_money(row["requested_cost_usd"], "requested_cost_usd")
            failure_reason = (
                "authoritative provider actual cost exceeds the USD 4.00 local reservation; "
                "budget failure"
                if over_cap
                else "reference provider action failed before call identity persistence"
            )
            cursor = connection.execute(
                """UPDATE budget_reservations SET status = ?, app_identity = ?,
                    provider_actual_cost_usd = ?, settlement_pending_at = ?,
                    settlement_identity = ?, failure_reason = ?, heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status = 'audit_blocked'
                  AND app_identity IS NULL AND provider_job_id IS NULL
                  AND settlement_pending_at IS NULL""",
                (
                    "failed",
                    evidence.app_id,
                    evidence.actual_cost_usd,
                    evidence.query_end.isoformat(),
                    evidence.receipt_sha256,
                    failure_reason,
                    occurred_at,
                    occurred_at,
                    reservation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("replacement settlement lost its compare-and-set")
            run_cursor = connection.execute(
                """UPDATE experiments SET status = 'failed', modal_cost_actual_usd = ?,
                    failure_reason = ?, ended_at = ? WHERE run_id = ? AND status = 'created'""",
                (evidence.actual_cost_usd, failure_reason, occurred_at, row["run_id"]),
            )
            if run_cursor.rowcount != 1:
                raise DatabaseError("replacement run settlement lost its compare-and-set")
            connection.execute(
                """INSERT INTO state_transitions(
                    run_id, from_state, to_state, reason, occurred_at
                ) VALUES (?, 'created', 'failed', ?, ?)""",
                (row["run_id"], failure_reason, occurred_at),
            )
        if over_cap:
            raise DatabaseError(
                "authoritative provider cost was recorded as a terminal budget failure"
            )
        return evidence.receipt_sha256

    def settle_reference_additional_billing(
        self,
        receipt_bytes: bytes,
        identity_evidence_bytes: bytes,
        filtered_report_bytes: bytes,
        *,
        pre_auth_receipt_bytes: bytes,
        post_auth_receipt_bytes: bytes,
        billing_authority_bytes: bytes,
        bootstrap_request_bytes: bytes,
        remote_receipt_bytes: bytes | None,
        occurred_at: str,
    ) -> str:
        """Settle the final grant without conflating billing and experiment outcome."""
        from lowbit_lab.reference_bootstrap import (
            ReferenceBootstrapError,
            validate_bootstrap_receipt_bytes,
            validate_bootstrap_request_bytes,
        )
        from lowbit_lab.reference_contract import additional_reference_binding
        from lowbit_lab.reference_replacement_settlement import (
            ReplacementSettlementError,
            validate_additional_settlement,
        )

        self.initialize()
        occurred = _database_timestamp(occurred_at, "occurred_at")
        try:
            selector = json.loads(receipt_bytes)
            reservation_id = selector["reservation_id"]
            authority = json.loads(billing_authority_bytes)
        except (TypeError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
            raise DatabaseError("additional settlement selector is invalid") from exc
        if not isinstance(reservation_id, str) or not isinstance(authority, dict):
            raise DatabaseError("additional settlement selector is invalid")
        if (
            set(authority)
            != {
                "schema_version",
                "kind",
                "provider",
                "environment_scope_sha256",
                "attribution_method_sha256",
                "authoritative_report_identity_sha256",
                "billing_completeness_delay_seconds",
            }
            or authority.get("schema_version") != 2
            or authority.get("kind") != "provider_billing_authority_contract"
            or authority.get("provider") != "modal"
        ):
            raise DatabaseError("additional billing authority is invalid")
        budget_failure = False
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT br.run_id, br.reference_execution_scope_sha256,
                    br.requested_cost_usd, br.status, br.provider_job_id, br.app_identity,
                    br.settlement_identity, br.provider_actual_cost_usd, br.heartbeat_at,
                    br.billing_authority_sha256, br.authoritative_report_identity_sha256,
                    br.billing_completeness_delay_seconds, e.status AS run_status,
                    e.config_sha256, e.config_json, rag.authority_sha256, rag.consumed_at,
                    rac.challenge_sha256, rac.packet_sha256,
                    rps.auth_binding_sha256, rws.original_workspace_scope_sha256,
                    rws.authenticated_workspace_identity_sha256,
                    rws.authority_sha256 AS reconciliation_authority_sha256
                FROM budget_reservations AS br
                JOIN experiments AS e ON e.run_id = br.run_id
                JOIN reference_additional_grants AS rag
                  ON rag.active_reservation_id = br.reservation_id
                JOIN reference_approval_challenges AS rac ON rac.run_id = br.run_id
                JOIN budget_reservations AS prior
                  ON prior.settlement_identity = rag.prior_settlement_receipt_sha256
                JOIN reference_replacement_entitlements AS rre
                  ON rre.replacement_reservation_id = prior.reservation_id
                JOIN reference_preidentity_settlements AS rps
                  ON rps.settlement_sha256 = rre.settlement_sha256
                JOIN reference_workspace_scope_reconciliations AS rws
                  ON rws.authority_sha256 = rre.workspace_reconciliation_authority_sha256
                WHERE br.reservation_id = ? AND rag.state = 'consumed'""",
                (reservation_id,),
            ).fetchone()
            if row is None or not _reference_boundary_consumed(
                connection,
                reservation_id=reservation_id,
                execution_scope_sha256=row["reference_execution_scope_sha256"],
            ):
                raise DatabaseError("additional reservation is not settlement-eligible")
            try:
                config_challenge, config = _reference_challenge(
                    row["config_json"], row["config_sha256"]
                )
                request = validate_bootstrap_request_bytes(bootstrap_request_bytes)
                binding = additional_reference_binding(
                    config_sha256=row["config_sha256"],
                    config_challenge_sha256=config_challenge,
                    request_sha256=request.sha256,
                    execution_scope_sha256=row["reference_execution_scope_sha256"],
                )
                if (
                    binding.challenge_sha256 != row["challenge_sha256"]
                    or binding.packet_sha256 != row["packet_sha256"]
                    or json.loads(request.canonical_json)["action"]
                    != "u8_reference_additional_once"
                ):
                    raise DatabaseError("additional request packet lineage drift")
                environment_scope_sha256 = config["provider"]["environment_scope_sha256"]
                if (
                    hashlib.sha256(billing_authority_bytes).hexdigest()
                    != row["billing_authority_sha256"]
                    or authority["environment_scope_sha256"] != environment_scope_sha256
                    or authority["authoritative_report_identity_sha256"]
                    != row["authoritative_report_identity_sha256"]
                    or authority["billing_completeness_delay_seconds"]
                    != row["billing_completeness_delay_seconds"]
                ):
                    raise DatabaseError("additional billing authority lineage drift")
                evidence = validate_additional_settlement(
                    receipt_bytes,
                    identity_evidence_bytes,
                    filtered_report_bytes,
                    pre_auth_receipt_bytes=pre_auth_receipt_bytes,
                    post_auth_receipt_bytes=post_auth_receipt_bytes,
                    expected_reservation_id=reservation_id,
                    expected_execution_scope_sha256=row["reference_execution_scope_sha256"],
                    expected_additional_authority_sha256=row["authority_sha256"],
                    expected_environment_scope_sha256=environment_scope_sha256,
                    expected_original_workspace_scope_sha256=row[
                        "original_workspace_scope_sha256"
                    ],
                    expected_workspace_identity_sha256=row[
                        "authenticated_workspace_identity_sha256"
                    ],
                    expected_reconciliation_authority_sha256=row[
                        "reconciliation_authority_sha256"
                    ],
                    expected_auth_binding_sha256=row["auth_binding_sha256"],
                    expected_billing_authority_sha256=row["billing_authority_sha256"],
                    expected_billing_method_sha256=authority["attribution_method_sha256"],
                    expected_report_identity_sha256=row[
                        "authoritative_report_identity_sha256"
                    ],
                    action_consumed_at=_database_timestamp(
                        row["consumed_at"], "additional consumed_at"
                    ),
                    latest_boundary_at=_database_timestamp(
                        row["heartbeat_at"], "additional heartbeat_at"
                    ),
                    maximum_action_seconds=int(REFERENCE_RESOURCES["timeout_seconds"]),
                    expected_completeness_delay_seconds=row[
                        "billing_completeness_delay_seconds"
                    ],
                    validated_at=occurred,
                )
            except (
                KeyError,
                TypeError,
                json.JSONDecodeError,
                ReferenceBootstrapError,
                ReplacementSettlementError,
                ValueError,
            ) as exc:
                raise DatabaseError("additional settlement evidence validation failed") from exc
            replay = row["status"] in {"settled", "failed"}
            if replay and (
                row["settlement_identity"] != evidence.receipt_sha256
                or row["provider_actual_cost_usd"] != evidence.actual_cost_usd
                or row["run_status"] not in TERMINAL_STATES
            ):
                raise DatabaseError("additional settlement replay drift")
            if not replay and row["status"] not in {
                "submission_pending",
                "submitted",
                "settlement_pending",
                "audit_blocked",
            }:
                raise DatabaseError("additional reservation is not settlement-eligible")
            if not replay and row["run_status"] != "created":
                raise DatabaseError("additional reservation is not settlement-eligible")
            execution_status = "unknown"
            full_context_proven = False
            if evidence.execution_receipt_sha256 is not None:
                if remote_receipt_bytes is None or hashlib.sha256(
                    remote_receipt_bytes
                ).hexdigest() != evidence.execution_receipt_sha256:
                    raise DatabaseError("additional execution receipt bytes mismatch")
                validated_receipt = validate_bootstrap_receipt_bytes(
                    remote_receipt_bytes, request=request
                )
                execution_status = validated_receipt.status
                full_context_proven = validated_receipt.full_context_usefulness_proven
                artifact = connection.execute(
                    """SELECT sha256 FROM artifacts
                    WHERE run_id = ? AND kind = 'bootstrap_receipt'""",
                    (row["run_id"],),
                ).fetchall()
                if len(artifact) != 1 or artifact[0]["sha256"] != evidence.execution_receipt_sha256:
                    raise DatabaseError("additional execution receipt is not durably recorded")
                manifests = connection.execute(
                    """SELECT sha256 FROM artifacts
                    WHERE run_id = ? AND kind = 'reference_manifest'""",
                    (row["run_id"],),
                ).fetchall()
                expected_manifest = evidence.execution_manifest_sha256
                if (expected_manifest is None and manifests) or (
                    expected_manifest is not None
                    and (len(manifests) != 1 or manifests[0]["sha256"] != expected_manifest)
                ):
                    raise DatabaseError("additional execution manifest lineage drift")
                if execution_status == "succeeded" and expected_manifest is None:
                    raise DatabaseError("successful additional execution lacks locked evidence")
            elif remote_receipt_bytes is not None:
                raise DatabaseError("unbound additional execution receipt is forbidden")
            if replay:
                return evidence.receipt_sha256
            expected_identity = {
                "call": row["provider_job_id"],
                "app": row["app_identity"],
                "billing_only": None,
                "workspace_zero_preidentity": None,
            }[evidence.attribution_mode]
            if evidence.attribution_mode in {"call", "app"}:
                if expected_identity is None or expected_identity != evidence.provider_identity:
                    raise DatabaseError("additional durable provider identity drift")
            elif row["provider_job_id"] is not None or row["app_identity"] is not None:
                raise DatabaseError("additional billing-only identity conflicts with durable state")
            actual = _database_actual_money(evidence.actual_cost_usd, "actual_cost_usd")
            over_cap = actual > _database_money(row["requested_cost_usd"], "requested_cost_usd")
            experiment_success = execution_status == "succeeded" and not over_cap
            failure_reason = None
            if over_cap:
                failure_reason = (
                    "authoritative provider actual cost exceeds the USD 4.00 local reservation; "
                    "budget failure"
                )
            elif execution_status == "failed":
                failure_reason = "validated reference execution receipt reported failure"
            elif execution_status == "unknown":
                failure_reason = "reference provider outcome was not authoritatively established"
            reservation_status = "failed" if over_cap else "settled"
            cursor = connection.execute(
                """UPDATE budget_reservations SET status = ?, provider_job_id =
                    CASE WHEN ? = 'call' THEN ? ELSE provider_job_id END,
                    app_identity = CASE WHEN ? IN ('app', 'billing_only') THEN ?
                        ELSE app_identity END,
                    provider_actual_cost_usd = ?, settlement_pending_at = ?,
                    settlement_identity = ?, settlement_mode = ?, failure_reason = ?,
                    heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND status IN (
                    'submission_pending', 'submitted', 'settlement_pending', 'audit_blocked'
                )""",
                (
                    reservation_status,
                    evidence.attribution_mode,
                    evidence.provider_identity,
                    evidence.attribution_mode,
                    evidence.provider_identity,
                    evidence.actual_cost_usd,
                    evidence.query_end.isoformat(),
                    evidence.receipt_sha256,
                    (
                        "workspace_zero_preidentity"
                        if evidence.attribution_mode == "workspace_zero_preidentity"
                        else None
                    ),
                    failure_reason,
                    occurred_at,
                    occurred_at,
                    reservation_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("additional settlement lost its compare-and-set")
            for from_state, to_state in (
                ("created", "validated"),
                ("validated", "running"),
            ):
                connection.execute(
                    "UPDATE experiments SET status = ? WHERE run_id = ? AND status = ?",
                    (to_state, row["run_id"], from_state),
                )
                connection.execute(
                    """INSERT INTO state_transitions(
                        run_id, from_state, to_state, reason, occurred_at
                    ) VALUES (?, ?, ?, NULL, ?)""",
                    (row["run_id"], from_state, to_state, occurred_at),
                )
            terminal = "completed" if experiment_success else "failed"
            run_cursor = connection.execute(
                """UPDATE experiments SET status = ?, modal_cost_actual_usd = ?,
                    failure_reason = ?, ended_at = ? WHERE run_id = ? AND status = 'running'""",
                (
                    terminal,
                    evidence.actual_cost_usd,
                    failure_reason,
                    occurred_at,
                    row["run_id"],
                ),
            )
            if run_cursor.rowcount != 1:
                raise DatabaseError("additional run settlement lost its compare-and-set")
            connection.execute(
                """INSERT INTO state_transitions(
                    run_id, from_state, to_state, reason, occurred_at
                ) VALUES (?, 'running', ?, ?, ?)""",
                (row["run_id"], terminal, failure_reason, occurred_at),
            )
            connection.execute(
                """INSERT INTO metrics(run_id, name, value_json, unit)
                VALUES (?, 'configured_context_tokens', '262144', 'tokens')""",
                (row["run_id"],),
            )
            if experiment_success and full_context_proven:
                connection.execute(
                    """INSERT INTO metrics(run_id, name, value_json, unit)
                    VALUES (?, 'proven_useful_context_tokens', '262144', 'tokens')""",
                    (row["run_id"],),
                )
            budget_failure = over_cap
        if budget_failure:
            raise DatabaseError(
                "authoritative provider cost was recorded as a terminal budget failure"
            )
        return evidence.receipt_sha256

    def reference_replacement_entitlement(self) -> dict[str, Any] | None:
        """Return the immutable replacement slot without mutating authority."""
        with self.connect_readonly() as connection:
            rows = connection.execute(
                "SELECT * FROM reference_replacement_entitlements LIMIT 2"
            ).fetchall()
        if len(rows) > 1:
            raise DatabaseError("multiple reference replacement entitlements are invalid")
        return None if not rows else dict(rows[0])

    def mark_reference_replacement_submission_pending(
        self,
        reservation_id: str,
        *,
        entitlement_sha256: str,
        owner_id: str,
        recovery_authority_sha256: str,
        auth_receipt_bytes: bytes,
        auth_binding_sha256: str,
        original_workspace_scope_sha256: str,
        authenticated_workspace_identity_sha256: str,
        workspace_reconciliation_authority_sha256: str,
        authority_root: Path,
        occurred_at: str,
        recovery_authority_path: Path = RECOVERY_AUTHORITY_PATH,
    ) -> None:
        """Consume the child entitlement at the final provider boundary, never before."""
        occurred = _database_timestamp(occurred_at, "occurred_at")
        _database_sha256(entitlement_sha256, "entitlement_sha256")
        _database_sha256(auth_binding_sha256, "auth_binding_sha256")
        _database_sha256(original_workspace_scope_sha256, "original_workspace_scope_sha256")
        _database_sha256(
            authenticated_workspace_identity_sha256,
            "authenticated_workspace_identity_sha256",
        )
        _database_sha256(
            workspace_reconciliation_authority_sha256,
            "workspace_reconciliation_authority_sha256",
        )
        if not owner_id or recovery_authority_sha256 != REFERENCE_RECOVERY_AUTHORITY_SHA256:
            raise DatabaseError("reference replacement boundary authority is invalid")
        try:
            validated = validate_reference_recovery_authority(
                authority_root, recovery_authority_path
            )
            reconciliation = validate_workspace_scope_reconciliation_authority(
                authority_root, WORKSPACE_RECONCILIATION_AUTHORITY_PATH
            )
        except ReferenceAuthorityError as exc:
            raise DatabaseError("reference replacement authority files are invalid") from exc
        if (
            validated != recovery_authority_sha256
            or sha256_json(reconciliation) != workspace_reconciliation_authority_sha256
            or reconciliation["original_workspace_scope_sha256"] != original_workspace_scope_sha256
            or reconciliation["authenticated_workspace_identity_sha256"]
            != authenticated_workspace_identity_sha256
        ):
            raise DatabaseError("reference replacement authority lineage mismatch")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT br.reference_execution_scope_sha256, br.lease_expires_at,
                    br.heartbeat_at, rre.original_execution_scope_sha256,
                    rps.original_workspace_scope_sha256,
                    rps.authenticated_workspace_identity_sha256,
                    rps.workspace_reconciliation_authority_sha256,
                    rps.auth_binding_sha256
                FROM budget_reservations AS br
                JOIN reference_replacement_entitlements AS rre
                  ON rre.entitlement_sha256 = ?
                JOIN reference_preidentity_settlements AS rps
                  ON rps.settlement_sha256 = rre.settlement_sha256
                WHERE br.reservation_id = ? AND br.owner_id = ? AND br.status = 'reserved'
                  AND rre.state = 'available'
                  AND rre.recovery_authority_sha256 = ?""",
                (
                    entitlement_sha256,
                    reservation_id,
                    owner_id,
                    recovery_authority_sha256,
                ),
            ).fetchone()
            if (
                row is None
                or row["reference_execution_scope_sha256"] != row["original_execution_scope_sha256"]
                or row["original_workspace_scope_sha256"] != original_workspace_scope_sha256
                or row["authenticated_workspace_identity_sha256"]
                != authenticated_workspace_identity_sha256
                or row["workspace_reconciliation_authority_sha256"]
                != workspace_reconciliation_authority_sha256
                or row["auth_binding_sha256"] != auth_binding_sha256
            ):
                raise DatabaseError("reference replacement is not ready for provider contact")
            try:
                auth_receipt = validate_workspace_auth_receipt(
                    auth_receipt_bytes,
                    expected_original_workspace_scope_sha256=(original_workspace_scope_sha256),
                    expected_authenticated_workspace_identity_sha256=(
                        authenticated_workspace_identity_sha256
                    ),
                    expected_reconciliation_authority_sha256=(
                        workspace_reconciliation_authority_sha256
                    ),
                    expected_binding_sha256=auth_binding_sha256,
                    validated_at=occurred,
                    maximum_age_seconds=AUTH_RECEIPT_MAXIMUM_AGE_SECONDS,
                )
            except ReferenceSettlementError as exc:
                raise DatabaseError("reference replacement auth receipt is invalid") from exc
            if occurred < _database_timestamp(row["heartbeat_at"], "stored heartbeat_at"):
                raise DatabaseError("reference replacement provider-contact time is backdated")
            if occurred > _database_timestamp(row["lease_expires_at"], "stored lease_expires_at"):
                raise DatabaseError("reference replacement reservation lease has expired")
            if _committed_provider_smoke_cost(connection) != REFERENCE_SETTLED_SMOKE_USD:
                raise DatabaseError("reference replacement smoke lineage has drifted")
            if _committed_provider_cost(connection) > REFERENCE_CUMULATIVE_CAP_USD:
                raise DatabaseError("reference replacement exceeds cumulative cap")
            cursor = connection.execute(
                """UPDATE reference_replacement_entitlements
                SET state = 'consumed', replacement_reservation_id = ?,
                    replacement_execution_scope_sha256 = ?, consumed_at = ?,
                    consumed_auth_receipt_sha256 = ?
                WHERE entitlement_sha256 = ? AND state = 'available'
                  AND replacement_reservation_id IS NULL""",
                (
                    reservation_id,
                    row["reference_execution_scope_sha256"],
                    occurred_at,
                    auth_receipt.receipt_sha256,
                    entitlement_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference replacement entitlement was already consumed")
            cursor = connection.execute(
                """UPDATE budget_reservations
                SET status = 'submission_pending', heartbeat_at = ?, updated_at = ?
                WHERE reservation_id = ? AND owner_id = ? AND status = 'reserved'""",
                (occurred_at, occurred_at, reservation_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError("reference replacement boundary transition failed")

    def get_reservation(self, reservation_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown reservation: {reservation_id}")
            return dict(row)

    def reconcile_stale_reservations(self, *, now: str) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {"released": [], "audit_blocked": []}
        now_time = _database_timestamp(now, "now")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT reservation_id, status, lease_expires_at FROM budget_reservations
                WHERE status IN (
                    'reserved', 'submission_pending', 'submitted', 'settlement_pending'
                )
                ORDER BY reservation_id""",
            ).fetchall()
            for row in rows:
                if (
                    _database_timestamp(row["lease_expires_at"], "stored lease_expires_at")
                    >= now_time
                ):
                    continue
                next_state = "released" if row["status"] == "reserved" else "audit_blocked"
                reason = (
                    "stale reservation released before submission"
                    if next_state == "released"
                    else "provider state or billing attribution requires manual audit"
                )
                cursor = connection.execute(
                    """UPDATE budget_reservations SET status = ?, failure_reason = ?,
                        heartbeat_at = ?, updated_at = ? WHERE reservation_id = ? AND status = ?""",
                    (next_state, reason, now, now, row["reservation_id"], row["status"]),
                )
                if cursor.rowcount == 1:
                    result[next_state].append(row["reservation_id"])
                    run = connection.execute(
                        "SELECT run_id, status FROM experiments WHERE run_id = ("
                        "SELECT run_id FROM budget_reservations WHERE reservation_id = ?)",
                        (row["reservation_id"],),
                    ).fetchone()
                    if run is not None and run["status"] not in TERMINAL_STATES:
                        if next_state == "released":
                            connection.execute(
                                """UPDATE experiments SET status = 'failed',
                                    modal_cost_actual_usd = '0', failure_reason = ?,
                                    ended_at = ? WHERE run_id = ?""",
                                (reason, now, run["run_id"]),
                            )
                            connection.execute(
                                """INSERT INTO state_transitions(
                                    run_id, from_state, to_state, reason, occurred_at
                                ) VALUES (?, ?, 'failed', ?, ?)""",
                                (run["run_id"], run["status"], reason, now),
                            )
                        else:
                            connection.execute(
                                "UPDATE experiments SET failure_reason = ? WHERE run_id = ?",
                                (reason, run["run_id"]),
                            )
        return result

    def start_activation_gate(
        self, gate_id: str, *, owner_id: str, heartbeat_at: str, lease_expires_at: str
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET status = 'running', heartbeat_at = ?, lease_expires_at = ?
                WHERE gate_id = ? AND owner_id = ? AND status = 'created'""",
                (heartbeat_at, lease_expires_at, gate_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"activation gate cannot start: {gate_id}")
            run_id = connection.execute(
                "SELECT run_id FROM activation_gates WHERE gate_id = ?", (gate_id,)
            ).fetchone()[0]
            connection.execute(
                """UPDATE experiments SET heartbeat_at = ?, lease_expires_at = ?
                WHERE run_id = ? AND owner_id = ?""",
                (heartbeat_at, lease_expires_at, run_id, owner_id),
            )

    def complete_activation_gate(
        self,
        gate_id: str,
        *,
        owner_id: str,
        evidence_json: str,
        evidence_sha256: str,
        ended_at: str,
        reused_gate_id: str | None = None,
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET status = 'completed', evidence_json = ?, evidence_sha256 = ?,
                    reused_gate_id = ?, ended_at = ?, heartbeat_at = ?
                WHERE gate_id = ? AND owner_id = ? AND status IN ('created', 'running')""",
                (
                    evidence_json,
                    evidence_sha256,
                    reused_gate_id,
                    ended_at,
                    ended_at,
                    gate_id,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"activation gate cannot complete: {gate_id}")

    def fail_activation_gate(
        self, gate_id: str, *, owner_id: str, reason: str, ended_at: str
    ) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET status = 'failed', failure_reason = ?, ended_at = ?, heartbeat_at = ?
                WHERE gate_id = ? AND owner_id = ? AND status IN ('created', 'running')""",
                (reason, ended_at, ended_at, gate_id, owner_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"activation gate cannot fail: {gate_id}")

    def fail_remaining_activation_gates(
        self, run_id: str, *, owner_id: str, reason: str, ended_at: str
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """UPDATE activation_gates
                SET status = 'failed', failure_reason = ?, ended_at = ?, heartbeat_at = ?
                WHERE run_id = ? AND owner_id = ? AND status IN ('created', 'running')""",
                (reason, ended_at, ended_at, run_id, owner_id),
            )

    def find_reusable_activation_gate(
        self, *, name: str, input_sha256: str, authority_sha256: str
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT * FROM activation_gates
                WHERE name = ? AND input_sha256 = ? AND authority_sha256 = ?
                  AND status = 'completed' AND evidence_valid = 1
                ORDER BY ended_at DESC, gate_id DESC LIMIT 1""",
                (name, input_sha256, authority_sha256),
            ).fetchone()
            return None if row is None else dict(row)

    def invalidate_activation_evidence(
        self,
        *,
        experiment_id: str,
        from_order: int,
        input_sha256: str,
        authority_sha256: str,
        reason: str,
        invalidated_at: str,
        current_run_id: str,
    ) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE activation_gates
                SET evidence_valid = 0, invalidated_at = ?, invalidation_reason = ?
                WHERE run_id IN (
                    SELECT gate.run_id
                    FROM activation_gates AS gate
                    JOIN experiments AS parent ON parent.run_id = gate.run_id
                    WHERE parent.experiment_id = ? AND gate.run_id != ?
                      AND gate.gate_order = ?
                      AND (gate.input_sha256 != ? OR gate.authority_sha256 != ?)
                ) AND gate_order >= ? AND status = 'completed' AND evidence_valid = 1""",
                (
                    invalidated_at,
                    reason,
                    experiment_id,
                    current_run_id,
                    from_order,
                    input_sha256,
                    authority_sha256,
                    from_order,
                ),
            )
            return cursor.rowcount

    def get_activation_gates(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM activation_gates WHERE run_id = ? ORDER BY gate_order", (run_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            if item["evidence_json"] is not None:
                item["evidence"] = json.loads(item.pop("evidence_json"))
            result.append(item)
        return result

    def reconcile_stale_activations(self, *, now: str) -> list[str]:
        reason = "activation interrupted before terminal persistence"
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT run_id, status FROM experiments
                WHERE mode = 'local_activation'
                  AND status NOT IN ('completed', 'failed')
                  AND lease_expires_at IS NOT NULL AND lease_expires_at < ?""",
                (now,),
            ).fetchall()
            run_ids = [row["run_id"] for row in rows]
            for row in rows:
                run_id = row["run_id"]
                connection.execute(
                    """UPDATE activation_gates SET status = 'failed', failure_reason = ?,
                        ended_at = ?, heartbeat_at = ?
                    WHERE run_id = ? AND status IN ('created', 'running')""",
                    (reason, now, now, run_id),
                )
                connection.execute(
                    """UPDATE experiments SET status = 'failed', failure_reason = ?, ended_at = ?,
                        heartbeat_at = ? WHERE run_id = ?""",
                    (reason, now, now, run_id),
                )
                connection.execute(
                    """INSERT INTO state_transitions(run_id, from_state, to_state, reason)
                    VALUES (?, ?, 'failed', ?)""",
                    (run_id, row["status"], reason),
                )
            return run_ids

    def create_attempt(
        self,
        *,
        attempt_id: str,
        config_path: str,
        raw_config_sha256: str | None,
        started_at: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO attempts(
                    attempt_id, config_path, raw_config_sha256, status, started_at
                ) VALUES (?, ?, ?, 'received', ?)""",
                (attempt_id, config_path, raw_config_sha256, started_at),
            )

    def link_attempt(self, attempt_id: str, run_id: str, ended_at: str) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE attempts SET status = 'linked', run_id = ?, ended_at = ?
                WHERE attempt_id = ? AND status = 'received'""",
                (run_id, ended_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"attempt cannot be linked: {attempt_id}")

    def fail_attempt(self, attempt_id: str, reason: str, ended_at: str) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                """UPDATE attempts SET status = 'failed', failure_reason = ?, ended_at = ?
                WHERE attempt_id = ? AND status = 'received'""",
                (reason, ended_at, attempt_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"attempt cannot be failed: {attempt_id}")

    def get_attempt(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown attempt: {attempt_id}")
            return dict(row)

    def transition(
        self, run_id: str, to_state: str, *, reason: str | None = None, ended_at: str | None = None
    ) -> None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT status FROM experiments WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown run: {run_id}")
            from_state = row["status"]
            if to_state not in TRANSITIONS[from_state]:
                raise DatabaseError(f"invalid transition: {from_state} -> {to_state}")
            if to_state in TERMINAL_STATES and ended_at is None:
                raise DatabaseError("terminal transition requires ended_at")
            if to_state == "failed" and not reason:
                raise DatabaseError("failed transition requires a reason")
            connection.execute(
                """UPDATE experiments
                SET status = ?, failure_reason = ?, ended_at = ?
                WHERE run_id = ?""",
                (to_state, reason if to_state == "failed" else None, ended_at, run_id),
            )
            connection.execute(
                """INSERT INTO state_transitions(run_id, from_state, to_state, reason)
                VALUES (?, ?, ?, ?)""",
                (run_id, from_state, to_state, reason),
            )

    def add_metric(self, run_id: str, name: str, value: Any, unit: str | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO metrics(run_id, name, value_json, unit) VALUES (?, ?, ?, ?)",
                (run_id, name, json.dumps(value, sort_keys=True, separators=(",", ":")), unit),
            )

    def add_artifact(
        self, run_id: str, *, path: str, sha256: str, size_bytes: int, kind: str
    ) -> None:
        artifact_path = _controller_artifact_path(path)
        artifact_sha256 = _database_sha256(sha256, "artifact_sha256")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise DatabaseError("artifact_size_bytes must be nonnegative")
        artifact_kind = _controller_identifier(kind, "artifact_kind")
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO artifacts(run_id, path, sha256, size_bytes, kind)
                VALUES (?, ?, ?, ?, ?)""",
                (run_id, artifact_path, artifact_sha256, size_bytes, artifact_kind),
            )

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM experiments WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"unknown run: {run_id}")
            result = dict(row)
            for key in ("config_json", "source_hashes_json", "runtime_json", "hardware_json"):
                result[key.removesuffix("_json")] = json.loads(result.pop(key))
            result["metrics"] = {
                item["name"]: {"value": json.loads(item["value_json"]), "unit": item["unit"]}
                for item in connection.execute("SELECT * FROM metrics WHERE run_id = ?", (run_id,))
            }
            result["transitions"] = [
                dict(item)
                for item in connection.execute(
                    """SELECT from_state, to_state, reason, occurred_at
                    FROM state_transitions WHERE run_id = ? ORDER BY id""",
                    (run_id,),
                )
            ]
            result["artifacts"] = [
                dict(item)
                for item in connection.execute(
                    """SELECT path, sha256, size_bytes, kind FROM artifacts
                    WHERE run_id = ? ORDER BY path""",
                    (run_id,),
                )
            ]
            return result

    def spend_totals(self, phase: int) -> tuple[str, str]:
        total = Decimal("0")
        phase_total = Decimal("0")
        with self.connect() as connection:
            for row in connection.execute("SELECT phase, modal_cost_actual_usd FROM experiments"):
                cost = Decimal(row["modal_cost_actual_usd"] or "0")
                total += cost
                if row["phase"] == phase:
                    phase_total += cost
        return format(phase_total, "f"), format(total, "f")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init", "show"])
    parser.add_argument("--db", type=Path, default=Path("results/results.sqlite"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id")
    args = parser.parse_args()
    database = ResultsDatabase(confine_results_db(args.root, args.db))
    database.initialize()
    if args.command == "show":
        if not args.run_id:
            parser.error("show requires --run-id")
        emit({"ok": True, "run": database.get_run(args.run_id)})
    else:
        emit({"ok": True, "database": str(args.db), "schema_version": SCHEMA_VERSION})


if __name__ == "__main__":
    main()
