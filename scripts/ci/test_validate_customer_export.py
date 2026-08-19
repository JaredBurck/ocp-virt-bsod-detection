"""Regression tests for scripts/ci/validate-customer-export.py.

The allowlist is the class-closing guard for the public GitHub export: a new
file under scripts/ or tests/ that is neither included nor excluded must fail
CI, and an exported tree must not contain Layer 1/2 or SBR-Virt disk URLs.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-customer-export.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_customer_export", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vce = _load_module()


@pytest.fixture
def mini_manifest(tmp_path):
    overlay = tmp_path / "docs" / "public"
    overlay.mkdir(parents=True)
    (overlay / "README.md").write_text("public readme\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "gate.sh").write_text("#!/bin/bash\n")
    (tmp_path / "scripts" / "secret.sh").write_text("internal only\n")
    (tmp_path / "alerts").mkdir()
    (tmp_path / "alerts" / "rules.yaml").write_text("groups: []\n")
    manifest = {
        "overlay_dir": "docs/public",
        "trees_full": ["alerts/"],
        "files": ["scripts/gate.sh"],
        "exclude_files": ["scripts/secret.sh"],
        "exclude_prefixes": [],
        "allowlist_prefixes": ["scripts/"],
        "deny_substrings": ["quay.io/sbr_virt", "gitlab.cee.redhat.com"],
        "deny_paths": ["insights-rules/", "must-gather/"],
        "deny_substring_exceptions": [],
    }
    return tmp_path, manifest


class TestUndeclared:
    def test_undeclared_script_fails(self, mini_manifest):
        repo, manifest = mini_manifest
        (repo / "scripts" / "new-tool.sh").write_text("echo hi\n")
        bad = vce.undeclared_under_allowlist(manifest, repo)
        assert "scripts/new-tool.sh" in bad

    def test_excluded_file_is_not_undeclared(self, mini_manifest):
        repo, manifest = mini_manifest
        bad = vce.undeclared_under_allowlist(manifest, repo)
        assert "scripts/secret.sh" not in bad
        assert "scripts/gate.sh" not in bad

    def test_exclude_prefix(self, mini_manifest):
        repo, manifest = mini_manifest
        lab = repo / "scripts" / "lab"
        lab.mkdir()
        (lab / "disk.yaml").write_text("internal\n")
        manifest["exclude_prefixes"] = ["scripts/lab/"]
        bad = vce.undeclared_under_allowlist(manifest, repo)
        assert "scripts/lab/disk.yaml" not in bad


class TestExportAndDeny:
    def test_export_drops_excluded_and_overlays_readme(self, mini_manifest, tmp_path):
        repo, manifest = mini_manifest
        dest = tmp_path / "dest"
        # export_tree reads overlay from repo
        vce.export_tree(dest, manifest, repo)
        assert (dest / "scripts" / "gate.sh").is_file()
        assert not (dest / "scripts" / "secret.sh").exists()
        assert (dest / "alerts" / "rules.yaml").is_file()
        assert (dest / "README.md").read_text() == "public readme\n"
        assert not (dest / "docs" / "public").exists()

    def test_deny_substring_caught(self, mini_manifest, tmp_path):
        repo, manifest = mini_manifest
        (repo / "alerts" / "rules.yaml").write_text(
            "runbook: https://gitlab.cee.redhat.com/internal\n")
        dest = tmp_path / "dest"
        vce.export_tree(dest, manifest, repo)
        errors = vce.deny_scan(dest, manifest)
        assert any("gitlab.cee.redhat.com" in e for e in errors)

    def test_deny_path_caught(self, mini_manifest, tmp_path):
        repo, manifest = mini_manifest
        dest = tmp_path / "dest"
        vce.export_tree(dest, manifest, repo)
        (dest / "must-gather").mkdir()
        (dest / "must-gather" / "Dockerfile").write_text("FROM scratch\n")
        errors = vce.deny_scan(dest, manifest)
        assert any("must-gather/" in e for e in errors)

    def test_exception_skips_substring(self, mini_manifest, tmp_path):
        repo, manifest = mini_manifest
        (repo / "alerts" / "rules.yaml").write_text("needle quay.io/sbr_virt\n")
        manifest["deny_substring_exceptions"] = ["alerts/rules.yaml"]
        dest = tmp_path / "dest"
        vce.export_tree(dest, manifest, repo)
        errors = vce.deny_scan(dest, manifest)
        assert errors == []


class TestRealManifest:
    def test_manifest_paths_exist(self):
        manifest = json.loads(
            (REPO_ROOT / "shared" / "customer-export-manifest.json").read_text())
        missing = [
            rel for rel in manifest["files"]
            if not (REPO_ROOT / rel).is_file()
        ]
        assert missing == [], missing

    def test_real_repo_has_no_undeclared(self):
        manifest = vce.load_manifest()
        assert vce.undeclared_under_allowlist(manifest) == []
