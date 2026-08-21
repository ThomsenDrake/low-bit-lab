from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from lowbit_lab.publication import PublicationError, load_manifest, main, scan_publication


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(repo: Path, message: str = "fixture") -> None:
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message)


def _repo_with_public_remote(tmp_path: Path) -> tuple[Path, Path]:
    remote = tmp_path / "public.git"
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "--bare", str(remote))
    _git(tmp_path, "init", "-b", "main", str(repo))
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "README.md").write_text("generic public scaffold\n", encoding="utf-8")
    (repo / ".gitignore").write_text(
        "configs/local/\ndocs/plans/local/\neval/local/\nartifacts/local/\nresults/local/\n"
        "reports/local/\n",
        encoding="utf-8",
    )
    _commit(repo, "initial")
    _git(repo, "remote", "add", "public", str(remote))
    _git(repo, "push", "-u", "public", "main")
    _git(repo, "remote", "set-head", "public", "main")
    return repo, remote


def test_clean_tracked_tree_passes_and_ignored_local_file_is_not_scanned(
    tmp_path: Path,
) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    (repo / ".gitignore").write_text("configs/local/\n", encoding="utf-8")
    _commit(repo, "ignore local authority")
    _git(repo, "push")
    local = repo / "configs/local/authority.yaml"
    local.parent.mkdir(parents=True)
    protected = "private-selected-identifier"
    local.write_text(protected, encoding="utf-8")

    result = scan_publication(repo, public_remote="public", protected_values=[protected])

    assert result["ok"] is True
    assert result["findings"] == []


def test_tracked_protected_identifier_fails_without_echoing_value(tmp_path: Path) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    protected = "private-selected-identifier"
    (repo / "tracked.txt").write_text(protected, encoding="utf-8")
    _git(repo, "add", "tracked.txt")

    result = scan_publication(repo, public_remote="public", protected_values=[protected])
    rendered = json.dumps(result)

    assert result["ok"] is False
    assert any(item["category"] == "configured_private_value" for item in result["findings"])
    assert protected not in rendered


@pytest.mark.parametrize(
    ("private_text", "category"),
    [
        ("C:" + r"\\Users\\private-user\\evidence.json", "private_path"),
        ("/" + "home/private-user/evidence.json", "private_path"),
        ("/mnt/" + "c/Users/private-user/evidence.json", "private_path"),
        ("GPU" + "-12345678-1234-1234-1234-123456789abc", "gpu_uuid"),
        ("token=" + "hf_" + "abcdefghijklmnopqrstuvwxyz123456", "credential"),
    ],
)
def test_private_patterns_fail_with_redacted_reasons(
    tmp_path: Path, private_text: str, category: str
) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    (repo / "tracked.txt").write_text(private_text, encoding="utf-8")
    _git(repo, "add", "tracked.txt")

    result = scan_publication(repo, public_remote="public", protected_values=[])
    rendered = json.dumps(result)

    assert result["ok"] is False
    assert any(item["category"] == category for item in result["findings"])
    assert private_text not in rendered


def test_forced_tracked_ignored_file_is_scanned(tmp_path: Path) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    (repo / ".gitignore").write_text("configs/local/\n", encoding="utf-8")
    _commit(repo, "ignore local authority")
    _git(repo, "push")
    protected = "private-selected-identifier"
    local = repo / "configs/local/authority.yaml"
    local.parent.mkdir(parents=True)
    local.write_text(protected, encoding="utf-8")
    _git(repo, "add", "-f", "configs/local/authority.yaml")

    result = scan_publication(repo, public_remote="public", protected_values=[protected])

    assert result["ok"] is False


def test_value_added_then_removed_in_unpushed_history_fails(tmp_path: Path) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    protected = "private-selected-identifier"
    leaked = repo / "temporary.txt"
    leaked.write_text(protected, encoding="utf-8")
    _commit(repo, "add private value")
    leaked.unlink()
    _git(repo, "add", "-u")
    _git(repo, "commit", "-m", "remove private value")

    result = scan_publication(repo, public_remote="public", protected_values=[protected])

    assert result["ok"] is False
    assert any(item["source"] == "outgoing_object" for item in result["findings"])


def test_unavailable_public_remote_base_fails_closed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-b", "main", str(repo))
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "README.md").write_text("generic\n", encoding="utf-8")
    _commit(repo)

    result = scan_publication(repo, public_remote="public", protected_values=[])

    assert result["ok"] is False
    assert result["findings"] == [{"category": "remote_base_unavailable", "source": "repository"}]


def test_ambiguous_public_remote_base_fails_closed(tmp_path: Path) -> None:
    repo, remote = _repo_with_public_remote(tmp_path)
    _git(repo, "symbolic-ref", "-d", "refs/remotes/public/HEAD")
    _git(repo, "switch", "-c", "other")
    (repo / "other.txt").write_text("generic\n", encoding="utf-8")
    _commit(repo, "other branch")
    _git(repo, "push", str(remote), "other:other")
    _git(repo, "fetch", "public")
    _git(repo, "switch", "main")

    result = scan_publication(repo, public_remote="public", protected_values=[])

    assert result["ok"] is False
    assert result["findings"] == [{"category": "remote_base_ambiguous", "source": "repository"}]


def test_local_manifest_is_confined_and_closed(tmp_path: Path) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    local = repo / "configs/local/publication.yaml"
    local.parent.mkdir(parents=True)
    local.write_text(
        "schema_version: 1\npublic_remote: public\nprivate_values:\n"
        "  - kind: target_identifier\n    value: private-selected-identifier\n",
        encoding="utf-8",
    )

    manifest = load_manifest(repo, Path("configs/local/publication.yaml"))

    assert manifest.public_remote == "public"
    assert manifest.private_values == ("private-selected-identifier",)
    with pytest.raises(PublicationError, match="ignored local directory"):
        load_manifest(repo, Path("publication.yaml"))


def test_manifest_rejects_unknown_keys_without_echoing_values(tmp_path: Path) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    local = repo / "configs/local/publication.yaml"
    local.parent.mkdir(parents=True)
    local.write_text(
        "schema_version: 1\npublic_remote: public\nprivate_values: []\nunknown: true\n",
        encoding="utf-8",
    )

    with pytest.raises(PublicationError, match="unknown keys"):
        load_manifest(repo, Path("configs/local/publication.yaml"))


def test_cli_emits_redacted_json_and_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo, _ = _repo_with_public_remote(tmp_path)
    protected = "private-selected-identifier"
    manifest = repo / "configs/local/publication.yaml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "schema_version: 1\npublic_remote: public\nprivate_values:\n"
        f"  - kind: target_identifier\n    value: {protected}\n",
        encoding="utf-8",
    )
    (repo / "tracked.txt").write_text(protected, encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    monkeypatch.setattr(
        sys,
        "argv",
        ["lowbit-publication", "--root", str(repo), "--manifest", str(manifest)],
    )

    with pytest.raises(SystemExit, match="1"):
        main()

    output = capsys.readouterr().out
    assert json.loads(output)["ok"] is False
    assert protected not in output
