from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from lowbit_lab.config import ConfigError, load_experiment_config, verify_sources

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
