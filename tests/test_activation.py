from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

import pytest
import yaml

from lowbit_lab.activation import (
    GATE_ORDER,
    ActivationAdapters,
    ActivationError,
    ActivationRequest,
    run_activation,
)
from lowbit_lab.db import ResultsDatabase
from lowbit_lab.provenance import load_metadata_policy
from lowbit_lab.runtime import load_runtime_lock

ROOT = Path(__file__).parents[1]


def _sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def make_activation(tmp_path: Path) -> tuple[ActivationRequest, Counter[str]]:
    for relative in (
        "configs/local",
        "docs/plans/local",
        "eval/local",
        "results/local",
        "artifacts/local",
    ):
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "PLAN.md", tmp_path / "PLAN.md")
    shutil.copy2(ROOT / "configs/budget-policy.json", tmp_path / "configs/budget-policy.json")
    shutil.copy2(
        ROOT / "configs/runtime-lock.example.json", tmp_path / "configs/local/runtime.json"
    )
    shutil.copy2(
        ROOT / "configs/metadata-policy.example.json", tmp_path / "configs/local/metadata.json"
    )
    (tmp_path / "configs/local/publication.yaml").write_text("schema_version: 1\n")
    (tmp_path / "docs/plans/local/approved.md").write_text("approved\n")
    (tmp_path / "configs/local/runtime-decision.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "declarations": [
                    {
                        "runtime_id": "generic-cuda-runtime",
                        "architecture_support": "declared",
                        "maintained_binary_available": True,
                        "license_and_provenance_verified": True,
                        "required_vram_bytes": 1,
                        "required_ram_bytes": 1,
                        "required_disk_bytes": 1,
                        "runtime_buffer_bytes": 1,
                        "kv_cache_bytes": 1,
                    }
                ],
                "measured": {
                    "vram_bytes": 3,
                    "ram_bytes": 3,
                    "disk_bytes": 3,
                    "runtime_buffer_bytes": 1,
                    "kv_cache_bytes": 1,
                },
            }
        )
    )
    (tmp_path / "eval/local/evaluation.json").write_text('{"status":"pending"}\n')
    runtime = load_runtime_lock(tmp_path / "configs/local/runtime.json", root=tmp_path)
    metadata = load_metadata_policy(tmp_path / "configs/local/metadata.json", root=tmp_path)
    raw = yaml.safe_load((ROOT / "configs/example-local-activation.yaml").read_text())
    raw["experiment_id"] = "generic-activation-test-v1"
    raw["target"].update(
        {
            "status": "configured",
            "identifier": "organization/repository",
            "revision": "a" * 40,
            "license": "example-license",
        }
    )
    raw["activation"].update(
        {
            "preview_only": False,
            "approved_plan_sha256": _sha(tmp_path / "docs/plans/local/approved.md"),
            "runtime_decision_sha256": _sha(
                tmp_path / "configs/local/runtime-decision.json"
            ),
            "runtime_lock_sha256": runtime.sha256,
            "metadata_policy_sha256": metadata.sha256,
            "evaluation_lock_sha256": _sha(tmp_path / "eval/local/evaluation.json"),
        }
    )
    raw["sources"][0]["sha256"] = _sha(tmp_path / "PLAN.md")
    (tmp_path / "configs/local/activation.yaml").write_text(yaml.safe_dump(raw))
    request = ActivationRequest(
        root=tmp_path,
        config_path=Path("configs/local/activation.yaml"),
        db_path=Path("results/local/activation.sqlite"),
        publication_manifest_path=Path("configs/local/publication.yaml"),
        approved_plan_path=Path("docs/plans/local/approved.md"),
        runtime_decision_path=Path("configs/local/runtime-decision.json"),
        runtime_lock_path=Path("configs/local/runtime.json"),
        metadata_policy_path=Path("configs/local/metadata.json"),
        evaluation_lock_path=Path("eval/local/evaluation.json"),
    )
    return request, Counter()


def adapters(calls: Counter[str], fail: str | None = None) -> ActivationAdapters:
    def gate(name: str):
        def run(_context):
            calls[name] += 1
            if name == fail:
                raise ActivationError("fixture failure")
            return {
                "ok": True,
                "gate": name,
                "promotion_authorized": False if name == "evaluation_lock" else None,
            }

        return run

    return ActivationAdapters(
        publication=gate("publication"),
        runtime_decision=gate("runtime_decision"),
        verified_local_runtime=gate("verified_local_runtime"),
        runtime_probe=gate("runtime_probe"),
        provenance=gate("provenance"),
        evaluation_lock=gate("evaluation_lock"),
    )


def test_preview_is_pure_and_reports_exact_caps_and_authority(tmp_path: Path) -> None:
    request, calls = make_activation(tmp_path)
    result = run_activation(request, apply=False, adapters=adapters(calls))
    assert result["gates"] == list(GATE_ORDER)
    assert result["side_effects_performed"] is False
    assert result["external_bytes"]["max_external_bytes"] == 37_748_759
    assert result["declared_authority_sha256"] == result["observed_authority_sha256"]
    assert not (tmp_path / request.db_path).exists()
    assert calls == Counter()


def test_success_is_terminal_zero_state_with_pending_promotion(tmp_path: Path) -> None:
    request, calls = make_activation(tmp_path)
    result = run_activation(request, apply=True, adapters=adapters(calls), owner_id="test-owner")
    assert result["run"]["status"] == "completed"
    assert result["run"]["modal_cost_requested_usd"] == "0"
    assert result["run"]["modal_cost_actual_usd"] == "0"
    assert [gate["status"] for gate in result["gates"]] == ["completed"] * len(GATE_ORDER)
    assert result["run"]["metrics"]["weights_loaded"]["value"] is False
    assert result["run"]["metrics"]["promotion_authorized"]["value"] is False


@pytest.mark.parametrize("failed_gate", GATE_ORDER[3:])
def test_action_gate_failure_stops_and_closes_every_child(
    tmp_path: Path, failed_gate: str
) -> None:
    request, calls = make_activation(tmp_path)
    with pytest.raises(ActivationError):
        run_activation(request, apply=True, adapters=adapters(calls, failed_gate))
    database = ResultsDatabase(tmp_path / request.db_path)
    with database.connect() as connection:
        run_id = connection.execute("SELECT run_id FROM experiments").fetchone()[0]
    run = database.get_run(run_id)
    gates = database.get_activation_gates(run_id)
    assert run["status"] == "failed"
    assert all(gate["status"] in {"completed", "failed"} for gate in gates)
    failed_index = GATE_ORDER.index(failed_gate)
    assert not any(calls[name] for name in GATE_ORDER[failed_index + 1 :])


def test_retry_gets_new_run_and_reexecutes_all_evidence_gates(tmp_path: Path) -> None:
    request, first_calls = make_activation(tmp_path)
    first = run_activation(request, apply=True, adapters=adapters(first_calls))
    second_calls: Counter[str] = Counter()
    second = run_activation(request, apply=True, adapters=adapters(second_calls))
    assert first["run"]["run_id"] != second["run"]["run_id"]
    assert second_calls == Counter({"publication": 1, **dict.fromkeys(GATE_ORDER[3:], 1)})
    assert all(gate["reused_gate_id"] is None for gate in second["gates"])


def test_publication_preflight_failure_is_audited_without_linking_run(tmp_path: Path) -> None:
    request, calls = make_activation(tmp_path)
    with pytest.raises(ActivationError):
        run_activation(request, apply=True, adapters=adapters(calls, "publication"))
    database = ResultsDatabase(tmp_path / request.db_path)
    with database.connect() as connection:
        attempt = connection.execute("SELECT * FROM attempts").fetchone()
        run_count = connection.execute("SELECT count(*) FROM experiments").fetchone()[0]
    assert attempt["status"] == "failed"
    assert attempt["run_id"] is None
    assert run_count == 0


def test_keyboard_interrupt_closes_linked_gate_and_parent(tmp_path: Path) -> None:
    request, calls = make_activation(tmp_path)

    def interrupt(_context):
        calls["runtime_probe"] += 1
        raise KeyboardInterrupt

    configured = adapters(calls)
    configured = ActivationAdapters(
        publication=configured.publication,
        runtime_decision=configured.runtime_decision,
        verified_local_runtime=configured.verified_local_runtime,
        runtime_probe=interrupt,
        provenance=configured.provenance,
        evaluation_lock=configured.evaluation_lock,
    )
    with pytest.raises(KeyboardInterrupt):
        run_activation(request, apply=True, adapters=configured)
    database = ResultsDatabase(tmp_path / request.db_path)
    with database.connect() as connection:
        run_id = connection.execute("SELECT run_id FROM experiments").fetchone()[0]
    assert database.get_run(run_id)["status"] == "failed"
    assert all(
        gate["status"] in {"completed", "failed"}
        for gate in database.get_activation_gates(run_id)
    )


def test_stale_nonterminal_parent_and_children_reconcile_failed(tmp_path: Path) -> None:
    request, _calls = make_activation(tmp_path)
    database = ResultsDatabase(tmp_path / request.db_path)
    database.initialize()
    config = yaml.safe_load((tmp_path / request.config_path).read_text())
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    database.create_run(
        run_id="stale-run",
        experiment_id=config["experiment_id"],
        config_sha256=hashlib.sha256(canonical.encode()).hexdigest(),
        config_json=canonical,
        source_hashes={},
        runtime={},
        hardware={},
        phase=1,
        mode="local_activation",
        requested_cost="0",
        started_at="2026-08-21T00:00:00+00:00",
        owner_id="dead-owner",
        heartbeat_at="2026-08-21T00:00:00+00:00",
        lease_expires_at="2026-08-21T00:00:01+00:00",
    )
    database.create_activation_gates(
        run_id="stale-run",
        owner_id="dead-owner",
        heartbeat_at="2026-08-21T00:00:00+00:00",
        lease_expires_at="2026-08-21T00:00:01+00:00",
        started_at="2026-08-21T00:00:00+00:00",
        gates=[
            {
                "gate_id": "stale-gate",
                "name": "runtime_probe",
                "input_sha256": "1" * 64,
                "authority_sha256": "2" * 64,
            }
        ],
    )
    assert database.reconcile_stale_activations(now="2026-08-21T00:01:00+00:00") == [
        "stale-run"
    ]
    assert database.get_run("stale-run")["status"] == "failed"
    assert database.get_activation_gates("stale-run")[0]["status"] == "failed"
