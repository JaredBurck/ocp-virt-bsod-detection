"""Regression tests for scripts/ci/validate-inhibit-rules.py.

F14 (v0.17.0 deep-dive review): pins the BEGIN/END marker extraction and
structural-check logic against synthetic file content, independent of
whether amtool is installed in the test environment (that path is exercised
separately, and skipped gracefully, by main() itself when amtool is absent).
"""
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-inhibit-rules.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_inhibit_rules", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vir = _load_module()

VALID_BLOCK = (
    "some header\n"
    "more header\n"
    "# BEGIN inhibit_rules\n"
    "# inhibit_rules:\n"
    "#   - source_matchers:\n"
    '#       - alertname = "BSODRisk_GuestCrash"\n'
    "#     target_matchers:\n"
    '#       - alertname = "VMNonRecoverableOSPanic"\n'
    '#     equal: ["name", "namespace"]\n'
    "# END inhibit_rules\n"
    "trailer\n"
)


class TestExtractCommentedYaml:
    def test_extracts_and_strips_prefix(self):
        result = vir.extract_commented_yaml(VALID_BLOCK)
        assert "inhibit_rules:" in result
        assert not any(line.startswith("#") for line in result.splitlines())

    def test_extracted_block_parses_as_yaml(self):
        import yaml
        result = vir.extract_commented_yaml(VALID_BLOCK)
        doc = yaml.safe_load(result)
        assert "inhibit_rules" in doc

    def test_missing_begin_marker_raises(self):
        with pytest.raises(ValueError, match="could not find"):
            vir.extract_commented_yaml("no markers here\n")

    def test_missing_end_marker_raises(self):
        with pytest.raises(ValueError, match="could not find"):
            vir.extract_commented_yaml("# BEGIN inhibit_rules\n# foo\n")

    def test_non_comment_line_inside_block_raises(self):
        bad = (
            "# BEGIN inhibit_rules\n"
            "not_a_comment: true\n"
            "# END inhibit_rules\n"
        )
        with pytest.raises(ValueError, match="not a '# '-prefixed comment"):
            vir.extract_commented_yaml(bad)

    def test_bare_hash_line_becomes_blank(self):
        block = (
            "# BEGIN inhibit_rules\n"
            "# inhibit_rules:\n"
            "#\n"
            "#   more: stuff\n"
            "# END inhibit_rules\n"
        )
        result = vir.extract_commented_yaml(block)
        lines = result.splitlines()
        assert lines[1] == ""


class TestCheckStructure:
    def _valid_doc(self):
        return {
            "inhibit_rules": [{
                "source_matchers": ['alertname = "BSODRisk_GuestCrash"'],
                "target_matchers": ['alertname = "VMNonRecoverableOSPanic"'],
                "equal": ["name", "namespace"],
            }]
        }

    def test_valid_doc_has_no_errors(self):
        assert vir.check_structure(self._valid_doc()) == []

    def test_missing_inhibit_rules_key(self):
        errors = vir.check_structure({})
        assert any("missing" in e for e in errors)

    def test_wrong_source_alert(self):
        doc = self._valid_doc()
        doc["inhibit_rules"][0]["source_matchers"] = ['alertname = "SomethingElse"']
        errors = vir.check_structure(doc)
        assert any("source_matchers" in e for e in errors)

    def test_wrong_target_alert(self):
        doc = self._valid_doc()
        doc["inhibit_rules"][0]["target_matchers"] = ['alertname = "SomethingElse"']
        errors = vir.check_structure(doc)
        assert any("target_matchers" in e for e in errors)

    def test_equal_missing_namespace_is_flagged(self):
        # Regression guard for the exact cross-VM misfire this design avoids:
        # matching on 'name' alone could inhibit an alert for a different VM
        # of the same name in another namespace.
        doc = self._valid_doc()
        doc["inhibit_rules"][0]["equal"] = ["name"]
        errors = vir.check_structure(doc)
        assert any("equal list" in e for e in errors)


class TestMainAgainstShippedFile:
    def test_shipped_file_structural_check_passes_without_amtool(self, monkeypatch):
        # Force the "amtool not found" path regardless of the test
        # environment's PATH, so this test is deterministic everywhere --
        # main() must still exit 0 (structural-only validation is not a
        # failure condition; only an actual amtool rejection is).
        monkeypatch.setattr(vir.shutil, "which", lambda _name: None)
        monkeypatch.setattr("sys.argv", ["validate-inhibit-rules.py"])
        assert vir.main() == 0

    def test_shipped_file_passes_real_amtool_if_available(self, monkeypatch):
        import shutil as _shutil
        amtool = _shutil.which("amtool")
        if not amtool:
            pytest.skip("amtool not installed in this test environment")
        monkeypatch.setattr("sys.argv", ["validate-inhibit-rules.py"])
        assert vir.main() == 0
