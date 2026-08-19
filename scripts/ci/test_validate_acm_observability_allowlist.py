"""Regression tests for scripts/ci/validate-acm-observability-allowlist.py.

The risk in this checker is over-broad matching: `rules:` is a legitimate key in
`acm/bsod-risk-policy.yaml` (embedded PrometheusRule `spec.groups[].rules`), and
a validator that flags three correct usages to catch one wrong one gets disabled
rather than obeyed. These tests pin that it is shape-aware, not string-matching.
"""
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-acm-observability-allowlist.py"

spec = importlib.util.spec_from_file_location("validate_acm_obs_allowlist", MODULE_PATH)
vaa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vaa)


def _cm(inner_key: str) -> str:
    return f"""\
kind: ConfigMap
apiVersion: v1
metadata:
  name: observability-metrics-custom-allowlist
  namespace: open-cluster-management-observability
data:
  metrics_list.yaml: |
    names:
      - bsod:cluster_risk_summary:gauge
    {inner_key}:
      - record: bsod:cluster_alert_count:gauge
        expr: count(ALERTS) or vector(0)
"""


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(vaa, "REPO_ROOT", tmp_path)
    (tmp_path / "acm").mkdir()
    monkeypatch.setattr(vaa, "ALLOWLIST",
                        tmp_path / "acm" / "observability-metrics-custom-allowlist.yaml")
    monkeypatch.setattr(vaa, "FAILURES", [])
    return tmp_path


def _cm_expr(expr: str) -> str:
    """A well-formed allowlist whose only variable is the recording rule's expr."""
    return f"""\
kind: ConfigMap
apiVersion: v1
metadata:
  name: observability-metrics-custom-allowlist
  namespace: open-cluster-management-observability
data:
  metrics_list.yaml: |
    names:
      - bsod:cluster_risk_summary:gauge
    recording_rules:
      - record: bsod:cluster_alert_count:gauge
        expr: {expr}
"""


class TestRecordingRuleQuoting:
    """R-48 -- found live on RHACM 2.17 after R-38 unblocked the block.

    The MCO JSON-encodes each rule onto the collector's command line as
    ``--recordingrule={"name":...,"query":"<expr>"}`` WITHOUT escaping double
    quotes inside <expr>. A double-quoted matcher closes the JSON string early,
    and the collector discards the rule every scrape with
    ``err="invalid character 'B' after object key:value pair"`` -- a warn-level
    line in the collector's own log and nothing anywhere else.
    """

    def test_double_quoted_matcher_is_flagged(self, fake_repo):
        vaa.ALLOWLIST.write_text(
            _cm_expr('count(ALERTS{alertname=~"BSODRisk_.*", alertstate="firing"})')
        )
        assert vaa.main() == 1

    def test_single_quoted_matcher_passes(self, fake_repo):
        vaa.ALLOWLIST.write_text(
            _cm_expr("count(ALERTS{alertname=~'BSODRisk_.*', alertstate='firing'})")
        )
        assert vaa.main() == 0

    def test_quoteless_expr_passes(self, fake_repo):
        vaa.ALLOWLIST.write_text(_cm_expr("count(ALERTS) or vector(0)"))
        assert vaa.main() == 0

    def test_double_quotes_outside_a_matcher_are_flagged_too(self, fake_repo):
        """Not only label matchers -- any double quote breaks the JSON encoding.

        `label_replace` takes bare string arguments, so this is a realistic way
        to reintroduce the defect without writing a matcher at all.
        """
        vaa.ALLOWLIST.write_text(
            _cm_expr('label_replace(count(ALERTS), "cluster", "$1", "instance", "(.*)")')
        )
        assert vaa.main() == 1

    def test_failure_message_names_the_rule_and_advises_single_quotes(self, fake_repo):
        vaa.ALLOWLIST.write_text(_cm_expr('count(ALERTS{alertstate="firing"})'))
        vaa.main()
        joined = " ".join(vaa.FAILURES)
        assert "bsod:cluster_alert_count:gauge" in joined
        assert "single quotes" in joined


class TestAllowlistKey:
    def test_bare_rules_key_is_flagged(self, fake_repo):
        vaa.ALLOWLIST.write_text(_cm("rules"))
        assert vaa.main() == 1

    def test_recording_rules_key_passes(self, fake_repo):
        vaa.ALLOWLIST.write_text(_cm("recording_rules"))
        assert vaa.main() == 0

    def test_names_only_passes(self, fake_repo):
        """Not every allowlist declares a recording rule."""
        vaa.ALLOWLIST.write_text(
            "kind: ConfigMap\napiVersion: v1\nmetadata:\n  name: x\n"
            "data:\n  metrics_list.yaml: |\n    names:\n      - bsod_foo\n")
        assert vaa.main() == 0

    def test_missing_body_is_flagged_not_silently_passed(self, fake_repo):
        """Finding nothing to check must fail loudly -- silently passing is how
        this class of bug survives a file restructure."""
        vaa.ALLOWLIST.write_text("kind: ConfigMap\napiVersion: v1\nmetadata:\n  name: x\ndata: {}\n")
        assert vaa.main() == 1


class TestNoOverBroadMatching:
    def test_prometheusrule_rules_key_is_not_flagged(self, fake_repo):
        """acm/bsod-risk-policy.yaml embeds PrometheusRule CRs whose
        spec.groups[].rules is correct. Only the allowlist ConfigMap's own
        metrics_list.yaml body is in scope, so this shape must be ignored."""
        vaa.ALLOWLIST.write_text("""\
kind: ConfigMap
apiVersion: v1
metadata:
  name: observability-metrics-custom-allowlist
data:
  metrics_list.yaml: |
    names:
      - bsod_foo
    recording_rules:
      - record: bsod:x:gauge
        expr: vector(0)
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: unrelated
spec:
  groups:
    - name: g
      rules:
        - alert: SomethingElse
          expr: up == 0
""")
        assert vaa.main() == 0, vaa.FAILURES


class TestRealRepo:
    def test_shipped_allowlist_is_clean(self):
        """Guards the real acm/ tree -- the assertion that would have failed
        before R-38."""
        vaa.FAILURES.clear()
        try:
            assert vaa.main() == 0, vaa.FAILURES
        finally:
            vaa.FAILURES.clear()
