import json
import shutil

from server import data_dir, data_version
from server.data import rules_hash


def copy_bundle(src, tmp_path):
    root = tmp_path / "bundle"
    shutil.copytree(src, root)
    return root


def test_data_dir_reads_the_named_variable(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    assert data_dir() == tmp_path


def test_data_dir_defaults_to_data(monkeypatch):
    monkeypatch.delenv("DATA_DIR")
    assert str(data_dir()) == "data"


def test_troubleshooting_tools_carry_no_corpus_generation():
    version = data_version(corpus=False)
    assert version["kb_generation"] is None
    assert version["rules_hash"].startswith("sha256:")


def test_rules_hash_is_stable(fixture_data_dir, tmp_path):
    root = copy_bundle(fixture_data_dir, tmp_path)
    assert rules_hash(root) == rules_hash.__wrapped__(root)


def test_rules_hash_changes_with_any_file(fixture_data_dir, tmp_path):
    root = copy_bundle(fixture_data_dir, tmp_path)
    before = rules_hash.__wrapped__(root)
    (root / "sop" / "signals.yaml").write_text("changed: {}\n")
    assert rules_hash.__wrapped__(root) != before


def test_rules_hash_ignores_hidden_files(fixture_data_dir, tmp_path):
    root = copy_bundle(fixture_data_dir, tmp_path)
    before = rules_hash.__wrapped__(root)
    (root / "sop" / ".DS_Store").write_bytes(b"\0")
    assert rules_hash.__wrapped__(root) == before


def test_the_manifest_wins_when_present(fixture_data_dir, tmp_path):
    root = copy_bundle(fixture_data_dir, tmp_path)
    (root / "manifest.json").write_text(json.dumps({"rules_hash": "sha256:published"}))
    assert rules_hash.__wrapped__(root) == "sha256:published"
