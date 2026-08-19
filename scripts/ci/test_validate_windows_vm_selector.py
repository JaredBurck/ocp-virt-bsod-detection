"""Regression tests for scripts/ci/validate-windows-vm-selector.py.

The validator's own extraction logic is the risky part: a paren-scan or regex
that silently stops matching turns "fail on drift" into "always pass", which is
worse than no check at all. Both extractors had exactly that bug on first write
(the select() scan truncated after one clause; the os_hint regex stopped at the
first `.get(...)`), so they are pinned here.
"""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-windows-vm-selector.py"

spec = importlib.util.spec_from_file_location("validate_windows_vm_selector", MODULE_PATH)
vws = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vws)


SELECT_BLOCK = '''\
  oc get vm -o json | jq -r '
    .items[]
    | select(
        (.spec.template.metadata.annotations["vm.kubevirt.io/os"] // "" | test("windows";"i"))
        or (.metadata.labels["vm.kubevirt.io/template"] // "" | test("windows";"i"))
        or (.spec.template.spec.domain.features.hyperv != null)
        or (.metadata.name | test("win";"i"))
      )
    | .metadata.name'
'''


class TestExtractSelects:
    def test_captures_the_whole_block_not_just_the_first_clause(self):
        """The original bug: the depth scan started at the newline after
        `select(`, so the first clause's own closing paren ended the scan."""
        blocks = vws._extract_selects(SELECT_BLOCK)
        assert len(blocks) == 1
        assert blocks[0].count("or ") == 3
        assert "metadata.name | test" in blocks[0]

    def test_ignores_unrelated_jq_selects(self):
        text = 'jq \'.items[] | select(\n  .status.phase == "Running"\n)\''
        assert vws._extract_selects(text) == []

    def test_normalise_ignores_indentation_only(self):
        a = vws._normalise("select(\n    x\n    or y\n  )")
        b = vws._normalise("select(\n        x\n        or y\n      )")
        assert a == b
        assert a != vws._normalise("select(\n    x\n  )")


class TestCanonicalSelector:
    def test_library_generates_a_non_empty_selector(self):
        """A selector that matches nothing would report a clean fleet."""
        sel = vws._canonical_selector()
        assert sel and "select(" in sel
        assert sel.count("or ") == 5  # 3 remaining os-hint fields + hyperv + name

    def test_generated_matches_every_shipped_implementation(self):
        """The assertion that would have failed before R-10."""
        vws.FAILURES.clear()
        try:
            assert vws.main() == 0, vws.FAILURES
        finally:
            vws.FAILURES.clear()

    def test_missing_jq_reported_distinctly_from_a_real_drift(self, monkeypatch):
        """CI (lint-bash) hit exactly this live: a before_script that never
        installed jq made wvs_build_selector return rc=1 with zero stdout --
        the generic "produced no selector" message reads identically to a
        genuine selector-logic drift. shutil.which is checked first so an
        environment/setup gap is never mistaken for a detection-logic bug."""
        monkeypatch.setattr(vws.shutil, "which", lambda _name: None)
        vws.FAILURES.clear()
        try:
            result = vws._canonical_selector()
            assert result is None
            assert len(vws.FAILURES) == 1
            assert "jq is not installed" in vws.FAILURES[0]
            assert "not a selector drift" in vws.FAILURES[0]
        finally:
            vws.FAILURES.clear()


class TestOsHintExtraction:
    def test_reads_every_field_the_selector_uses(self):
        """Pins the second extraction bug: a non-greedy `(.*?)\\)\\n` stopped at
        the first .get(...) and reported three false drifts."""
        import json
        cfg = json.loads((REPO_ROOT / "shared" / "windows-vm-selector.json").read_text())
        vws.FAILURES.clear()
        try:
            vws.check_python_os_hint(cfg)
            assert vws.FAILURES == [], vws.FAILURES
        finally:
            vws.FAILURES.clear()
