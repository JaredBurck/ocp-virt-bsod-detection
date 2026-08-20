"""Regression tests for scripts/ci/validate-rule-domain-coverage.py.

Peer-review finding F-05: `validate-shared-thresholds.py` pins the DIRECTION of
`score_finding()`'s unmapped-domain fallback (it must fail upward) but nothing
pinned its COVERAGE. A new rule with a prefix `_detect_domain()` does not
recognise would therefore score at the HIGHEST weight, silently inflating a
VM's risk tier, with no test objecting.

The risk is not hypothetical: `_detect_domain()` falls through to SUBSTRING
matching, and its own comments record three rules that were mis-scored that way
(N6 twice, F-03 once), each fixed by adding an explicit prefix branch ahead of
the substring rules.

What matters in these tests is that the validator still FAILS on each shape the
bug can take -- an unrecognised prefix in either rule_id spelling, and a weight
nothing maps to. A validator that only accepts the current tree proves nothing;
per CLAUDE.md's Design Rule 2, enumerate the shapes, then prove it fails on
them.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-rule-domain-coverage.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_rule_domain_coverage", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


val = _load_module()


@pytest.fixture
def fake_plugins(tmp_path, monkeypatch):
    """Point the extractor at a synthetic plugins dir."""
    plugins = tmp_path / "insights-rules" / "plugins"
    plugins.mkdir(parents=True)
    monkeypatch.setattr(val, "REPO", tmp_path)
    monkeypatch.setattr(val, "PLUGINS", plugins)
    return plugins


class TestCollectRuleIds:
    """Both spellings must be followed.

    Literal-only extraction would miss the f-string form used by
    BSOD_DRIVER_* and BSOD_PLATFORM_* -- and BSOD_PLATFORM_DRIVER_STREAM_CAPPED
    is exactly the rule whose domain misattribution (F-03) motivated this
    check. Missing it would make the validator blind to the case it exists for.
    """

    def test_finds_literal_rule_ids(self, fake_plugins):
        (fake_plugins / "a.py").write_text(
            'x = RuleResult(rule_id="BSOD_CPU_THING", severity="WARN")\n')
        assert "BSOD_CPU_THING" in val.collect_rule_ids()

    def test_finds_fstring_rule_ids(self, fake_plugins):
        (fake_plugins / "b.py").write_text(
            'RULE_PREFIX = "BSOD_DRIVER"\n'
            'x = RuleResult(rule_id=f"{RULE_PREFIX}_VERSION")\n')
        assert "BSOD_DRIVER_VERSION" in val.collect_rule_ids()

    def test_follows_multiple_prefix_vars(self, fake_plugins):
        """A file may define more than one prefix (driver + platform)."""
        (fake_plugins / "c.py").write_text(
            'RULE_PREFIX = "BSOD_DRIVER"\n'
            'RULE_PREFIX_PLATFORM = "BSOD_PLATFORM"\n'
            'a = RuleResult(rule_id=f"{RULE_PREFIX}_VERSION")\n'
            'b = RuleResult(rule_id=f"{RULE_PREFIX_PLATFORM}_DRIVER_STREAM_CAPPED")\n')
        ids = val.collect_rule_ids()
        assert "BSOD_DRIVER_VERSION" in ids
        assert "BSOD_PLATFORM_DRIVER_STREAM_CAPPED" in ids


class TestCoverage:
    def test_accepts_known_prefixes(self, fake_plugins):
        (fake_plugins / "a.py").write_text(
            'x = RuleResult(rule_id="BSOD_CPU_THING")\n'
            'y = RuleResult(rule_id="BSOD_STORAGE_THING")\n')
        errors = []
        assert val.check_coverage(errors) == 2
        assert errors == []

    def test_rejects_unmapped_prefix(self, fake_plugins):
        """The F-05 defect: a new rule nothing knows how to score."""
        (fake_plugins / "a.py").write_text(
            'x = RuleResult(rule_id="BSOD_NUMA_AFFINITY_BROKEN")\n')
        errors = []
        val.check_coverage(errors)
        assert len(errors) == 1
        assert "BSOD_NUMA_AFFINITY_BROKEN" in errors[0]
        assert "HIGHEST weight" in errors[0]

    def test_rejects_unmapped_prefix_in_fstring_form(self, fake_plugins):
        """Same defect, other spelling -- both doors must be closed."""
        (fake_plugins / "a.py").write_text(
            'RULE_PREFIX_NEW = "BSOD_QUANTUM"\n'
            'x = RuleResult(rule_id=f"{RULE_PREFIX_NEW}_ENTANGLED")\n')
        errors = []
        val.check_coverage(errors)
        assert len(errors) == 1
        assert "BSOD_QUANTUM_ENTANGLED" in errors[0]

    def test_empty_extraction_is_an_error(self, fake_plugins):
        """A guard that silently checks nothing while printing OK is worse
        than no guard -- this is how a validator rots into a no-op."""
        errors = []
        assert val.check_coverage(errors) == 0
        assert len(errors) == 1
        assert "no rule_ids were extracted" in errors[0]


class TestWeightSet:
    def test_flags_weight_nothing_maps_to(self, fake_plugins, monkeypatch):
        """Dead config, or a rule being claimed by a substring rule first."""
        (fake_plugins / "a.py").write_text(
            'x = RuleResult(rule_id="BSOD_CPU_THING")\n')
        monkeypatch.setitem(val.DOMAIN_WEIGHTS, "phantom_domain", 9.9)
        errors = []
        val.check_weight_set(errors, val.collect_rule_ids())
        assert any("phantom_domain" in e for e in errors)


class TestRealTree:
    """The shipped tree must satisfy the contract."""

    def test_repository_passes(self):
        assert val.main() == 0

    def test_every_shipped_rule_maps(self):
        """Explicit, readable statement of the property, independent of main()."""
        unmapped = {
            rid: str(src) for rid, src in val.collect_rule_ids().items()
            if val._detect_domain(rid) == val.UNMAPPED_DOMAIN
            or val._detect_domain(rid) not in val.DOMAIN_WEIGHTS
        }
        assert unmapped == {}, f"unmapped rule_ids: {unmapped}"
