"""Regression tests for scripts/ci/validate-acm-policy.py.

Peer-review item 17: --update used to prepend a fresh "GENERATED from
canonical sources" header on every run without stripping any header already
embedded in the round-tripped document, so headers accumulated without bound
(observed: 4 stacked copies in acm/bsod-risk-policy.yaml before this fix).
These tests assert both the header-stripping helper in isolation and full
idempotency of an actual --update run against the real policy file.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-acm-policy.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_acm_policy", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vap = _load_module()


class TestStripExistingHeaders:
    def test_no_header_is_unchanged(self):
        text = "apiVersion: v1\nkind: Policy\n"
        assert vap._strip_existing_headers(text) == text

    def test_single_header_is_stripped(self):
        text = vap.HEADER + "apiVersion: v1\nkind: Policy\n"
        assert vap._strip_existing_headers(text) == "apiVersion: v1\nkind: Policy\n"

    def test_multiple_stacked_headers_are_all_stripped(self):
        """Reproduces the exact pre-fix bug: repeated --update runs stacking
        the header block on top of itself, plus an older/differently-worded
        header variant from before the canonical-sources list changed."""
        old_variant = (
            "# GENERATED from canonical sources -- regenerate with:\n"
            "#   python3 scripts/ci/validate-acm-policy.py --update\n"
            "# Canonical sources:\n"
            "#   alerts/bsod-risk-prometheusrules.yaml (PrometheusRule spec.groups)\n"
            "#   dashboards/bsod-risk-dashboard-configmap.yaml (ConfigMap data)\n"
        )
        stacked = vap.HEADER + vap.HEADER + old_variant + "apiVersion: v1\nkind: Policy\n"
        assert vap._strip_existing_headers(stacked) == "apiVersion: v1\nkind: Policy\n"

    def test_only_leading_comment_lines_are_stripped(self):
        """A '#' comment that isn't part of the leading header block (e.g.
        an inline comment further down the document) must survive."""
        text = vap.HEADER + "apiVersion: v1\n# not a header, a real comment\nkind: Policy\n"
        result = vap._strip_existing_headers(text)
        assert result == "apiVersion: v1\n# not a header, a real comment\nkind: Policy\n"


class TestUpdateIsIdempotent:
    def test_real_policy_file_has_exactly_one_header(self):
        """Guards against the committed file itself regressing back to a
        stacked-header state between --update runs."""
        text = (REPO_ROOT / "acm" / "bsod-risk-policy.yaml").read_text()
        assert text.count("GENERATED from canonical sources") == 1


def test_cli_update_twice_is_a_noop_on_the_real_file(tmp_path):
    """Full subprocess-level idempotency check against the actual CLI entry
    point (not just the in-process module functions)."""
    real_policy = REPO_ROOT / "acm" / "bsod-risk-policy.yaml"
    before = real_policy.read_bytes()
    try:
        subprocess.run(
            [sys.executable, str(MODULE_PATH), "--update"],
            cwd=REPO_ROOT, check=True, capture_output=True,
        )
        after_first = real_policy.read_bytes()
        subprocess.run(
            [sys.executable, str(MODULE_PATH), "--update"],
            cwd=REPO_ROOT, check=True, capture_output=True,
        )
        after_second = real_policy.read_bytes()
        assert after_first == after_second
    finally:
        real_policy.write_bytes(before)
