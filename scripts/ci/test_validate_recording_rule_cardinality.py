"""Regression tests for scripts/ci/validate-recording-rule-cardinality.py.

F13 (v0.17.0 deep-dive review): pins the by()/count by() label extraction
regex and the allowlist-comparison logic against synthetic rule text, so a
future change to either cannot silently stop catching an unreviewed
high-cardinality label (the exact gap this validator exists to close --
docs/info/e2e-validation-r9-r10.md's "Cardinality Check" section documents
the real-world risk, but nothing enforced it in CI before this).
"""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-recording-rule-cardinality.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_recording_rule_cardinality", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vrrc = _load_module()


class TestExtractByLabels:
    def test_single_clause(self):
        expr = "sum by (name, namespace, drive) (rate(foo[1h]))"
        assert vrrc.extract_by_labels(expr) == ["name", "namespace", "drive"]

    def test_no_clause_returns_empty(self):
        assert vrrc.extract_by_labels("sum(bsod:vm_risk_factor_count:gauge) or vector(0)") == []

    def test_multiple_clauses_in_one_expr(self):
        expr = (
            "(\n"
            "  sum by (name, namespace, drive) (rate(a[1h]))\n"
            "    /\n"
            "  sum by (name, namespace, drive) (rate(b[1h]))\n"
            ")\n"
        )
        assert vrrc.extract_by_labels(expr) == [
            "name", "namespace", "drive", "name", "namespace", "drive",
        ]

    def test_multiline_by_clause(self):
        expr = (
            "count(\n"
            "  count by (\n"
            "    label_a,\n"
            "    label_b\n"
            "  ) (metric)\n"
            ") or vector(0)"
        )
        assert vrrc.extract_by_labels(expr) == ["label_a", "label_b"]

    def test_single_label_no_comma(self):
        assert vrrc.extract_by_labels("max by (vm_name) (metric)") == ["vm_name"]

    def test_ignores_bare_by_without_parens_content_mismatch(self):
        # "by" appearing as a substring of another identifier must not match.
        assert vrrc.extract_by_labels("some_metric_nearby(foo)") == []


class TestAllowlistEnforcement:
    def test_known_labels_all_on_allowlist(self):
        for label in ["name", "namespace", "drive", "vm_name",
                       "label_cpu_feature_node_kubevirt_io_pcid",
                       "label_cpu_feature_node_kubevirt_io_invpcid",
                       "label_cpu_feature_node_kubevirt_io_pku",
                       "label_cpu_feature_node_kubevirt_io_erms",
                       "label_cpu_feature_node_kubevirt_io_amd_psfd"]:
            assert label in vrrc.ALLOWED_BY_LABELS, (
                f"{label} is used by the shipped recording rules but missing "
                f"from ALLOWED_BY_LABELS"
            )

    def test_unreviewed_label_is_not_on_allowlist(self):
        # Sentinel: a label that must never accidentally end up allowlisted,
        # since it is exactly the kind of unbounded-cardinality identifier
        # this guard exists to catch (real Prometheus/kube-state-metrics
        # label, high/unbounded cardinality on any real cluster).
        assert "instance" not in vrrc.ALLOWED_BY_LABELS
        assert "pod" not in vrrc.ALLOWED_BY_LABELS
        assert "uid" not in vrrc.ALLOWED_BY_LABELS


class TestMainAgainstShippedFile:
    def test_shipped_recording_rules_pass_clean(self):
        # The real alerts/bsod-risk-recording-rules.yaml must pass with the
        # allowlist as shipped -- this is the "did I forget to update the
        # allowlist when I touched the rules file" regression guard.
        assert vrrc.main() == 0

    def test_new_unreviewed_label_fails(self, tmp_path, monkeypatch):
        rules_file = tmp_path / "recording-rules.yaml"
        rules_file.write_text(
            "apiVersion: monitoring.coreos.com/v1\n"
            "kind: PrometheusRule\n"
            "metadata:\n"
            "  name: test\n"
            "spec:\n"
            "  groups:\n"
            "    - name: test.recording\n"
            "      rules:\n"
            "        - record: test:new_metric:gauge\n"
            "          expr: |\n"
            "            sum by (totally_new_unbounded_label) (some_metric)\n"
        )
        monkeypatch.setattr(vrrc, "RULES_FILE", rules_file)
        assert vrrc.main() == 1

    def test_missing_rules_file_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(vrrc, "RULES_FILE", tmp_path / "does-not-exist.yaml")
        assert vrrc.main() == 1
