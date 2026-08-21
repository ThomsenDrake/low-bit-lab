from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from lowbit_lab.config import (
    ConfigError,
    load_experiment_config,
    verify_activation_authority,
    verify_sources,
)

ROOT = Path(__file__).parents[1]


def test_config_is_canonical_and_sources_verify() -> None:
    config = load_experiment_config(ROOT / "configs/example-local-dry-run.yaml")
    assert (
        config.sha256 == load_experiment_config(ROOT / "configs/example-local-dry-run.yaml").sha256
    )
    assert verify_sources(config, ROOT)["PLAN.md"] == config.sources[0].sha256
    assert config.configured_context_tokens == 32_768
    assert config.useful_context_proven is False
    assert config.target_status == "unconfigured"
    assert config.target_identifier is None


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update({"unknown": True}), "unknown keys"),
        (lambda value: value["modal"].update({"submit": True}), "submission is disabled"),
        (lambda value: value["context"].update({"useful_proven": True}), "cannot claim"),
        (
            lambda value: value["target"].update({"identifier": "organization/repository"}),
            "unconfigured target",
        ),
        (
            lambda value: value.update({"evaluations": ["coding", "unknown"]}),
            "unknown evaluations",
        ),
        (
            lambda value: value.update({"evaluations": ["coding", "coding"]}),
            "must be unique",
        ),
    ],
)
def test_config_rejects_unsafe_changes(tmp_path: Path, mutate, message: str) -> None:
    raw = yaml.safe_load((ROOT / "configs/example-local-dry-run.yaml").read_text())
    mutated = copy.deepcopy(raw)
    mutate(mutated)
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(mutated), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_experiment_config(path)


def test_configured_target_requires_immutable_revision(tmp_path: Path) -> None:
    raw = yaml.safe_load((ROOT / "configs/example-local-dry-run.yaml").read_text())
    raw["target"].update(
        {
            "status": "configured",
            "identifier": "organization/repository",
            "revision": "main",
            "license": "example-license",
        }
    )
    path = tmp_path / "bad-revision.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ConfigError, match="immutable lowercase hash"):
        load_experiment_config(path)


def test_configured_target_accepts_generic_immutable_lineage(tmp_path: Path) -> None:
    raw = yaml.safe_load((ROOT / "configs/example-local-dry-run.yaml").read_text())
    raw["target"].update(
        {
            "status": "configured",
            "identifier": "organization/repository",
            "revision": "a" * 40,
            "license": "example-license",
        }
    )
    path = tmp_path / "configured.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    config = load_experiment_config(path)
    assert config.target_identifier == "organization/repository"
    assert config.target_revision == "a" * 40


def _activation_config(*, preview_only: bool) -> dict:
    raw = yaml.safe_load((ROOT / "configs/example-local-dry-run.yaml").read_text())
    raw.update({"experiment_id": "generic-local-activation-v1", "phase": 1})
    raw["mode"] = "local_activation"
    raw["activation"] = {
        "preview_only": preview_only,
        "approved_plan_sha256": None if preview_only else "1" * 64,
        "runtime_decision_sha256": None if preview_only else "5" * 64,
        "runtime_lock_sha256": None if preview_only else "2" * 64,
        "metadata_policy_sha256": None if preview_only else "3" * 64,
        "evaluation_lock_sha256": None if preview_only else "4" * 64,
        "scheduling_enabled": False,
        "destructive_cleanup_enabled": False,
    }
    if not preview_only:
        raw["target"].update(
            {
                "status": "configured",
                "identifier": "organization/repository",
                "revision": "a" * 40,
                "license": "example-license",
            }
        )
    return raw


def test_activation_requires_explicit_preview_for_public_template() -> None:
    path = ROOT / "configs/example-local-activation.yaml"
    with pytest.raises(ConfigError, match="preview-only"):
        load_experiment_config(path)
    config = load_experiment_config(path, activation_preview=True)
    assert config.mode == "local_activation"
    assert config.activation is not None
    assert config.activation.preview_only is True
    assert config.target_status == "unconfigured"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update({"weights_required": True}), "weights_required"),
        (lambda value: value["modal"].update({"requested_cost_usd": "0.01"}), "cost"),
        (lambda value: value["modal"].update({"submit": True}), "submission"),
        (lambda value: value["modal"].update({"gpu_type": "remote-gpu"}), "GPU"),
        (lambda value: value["modal"].update({"gpu_count": 1}), "GPU"),
        (lambda value: value["privacy"].update({"allow_cloud_upload": True}), "upload"),
        (
            lambda value: value["activation"].update({"scheduling_enabled": True}),
            "scheduling",
        ),
        (
            lambda value: value["activation"].update({"destructive_cleanup_enabled": True}),
            "destructive cleanup",
        ),
        (lambda value: value["activation"].update({"approved_plan_sha256": None}), "hash"),
    ],
)
def test_executable_activation_rejects_unsafe_or_missing_authority(
    tmp_path: Path, mutate, message: str
) -> None:
    raw = _activation_config(preview_only=False)
    mutate(raw)
    path = tmp_path / "activation.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_experiment_config(path)


def test_executable_activation_requires_configured_target(tmp_path: Path) -> None:
    raw = _activation_config(preview_only=False)
    raw["target"] = {
        "status": "unconfigured",
        "identifier": None,
        "revision": None,
        "license": None,
        "tokenizer_path": None,
        "tokenizer_sha256": None,
    }
    path = tmp_path / "activation.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ConfigError, match="configured target"):
        load_experiment_config(path)


def test_executable_activation_rejects_changed_observed_authority_hash(tmp_path: Path) -> None:
    raw = _activation_config(preview_only=False)
    path = tmp_path / "activation.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    config = load_experiment_config(path)
    observed = config.activation.authority_hashes
    observed["runtime_lock_sha256"] = "f" * 64
    with pytest.raises(ConfigError, match="hash mismatch: runtime_lock_sha256"):
        verify_activation_authority(config, observed)
