"""Regression tests for scripts/ci/validate-public-layer34-docs.py."""
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-public-layer34-docs.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_public_layer34_docs", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vpl = _load_module()


@pytest.fixture
def public_tree(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "scripts").mkdir()
    runbook = tmp_path / "docs" / "admin-runbook.md"
    runbook.write_text(
        "\n".join([
            "## Gate checks",
            "",
            "| Gate | Check |",
            "|------|-------|",
            *[f"| {n} | check {n} |" for n in range(1, 22)],
            "",
            "## Gate behavior notes",
            "",
            "## Known limitations",
            "",
            "## virtio-win version matrix",
            "",
            "## Guest-side collector",
            "",
        ])
        + "\n"
    )
    (tmp_path / "README.md").write_text(
        "See [docs/admin-runbook.md](docs/admin-runbook.md).\n"
    )
    (tmp_path / "scripts" / "cnv-win-bsod-audit.sh").write_text(
        "echo hello\n"
    )
    return tmp_path


class TestAdminRunbook:
    def test_missing_heading_fails(self, public_tree):
        runbook = public_tree / "docs" / "admin-runbook.md"
        runbook.write_text(runbook.read_text().replace("## Known limitations", ""))
        errors = vpl.check_admin_runbook(public_tree, set(range(1, 22)))
        assert any("Known limitations" in e or "known limitations" in e.lower()
                   for e in errors)

    def test_missing_gate_row_fails(self, public_tree):
        runbook = public_tree / "docs" / "admin-runbook.md"
        text = runbook.read_text().replace("| 11 | check 11 |\n", "")
        runbook.write_text(text)
        errors = vpl.check_admin_runbook(public_tree, set(range(1, 22)))
        assert any("missing Gate" in e and "11" in e for e in errors)

    def test_complete_runbook_passes(self, public_tree):
        errors = vpl.check_admin_runbook(public_tree, set(range(1, 22)))
        assert errors == []


class TestForbiddenAndStale:
    def test_operator_runbook_link_fails(self, public_tree):
        (public_tree / "docs" / "admin-runbook.md").write_text(
            (public_tree / "docs" / "admin-runbook.md").read_text()
            + "\nSee docs/operator-runbook.md\n"
        )
        errors = vpl.check_forbidden_paths(public_tree)
        assert any("operator-runbook" in e for e in errors)

    def test_stale_gate11_fails(self, public_tree):
        (public_tree / "README.md").write_text(
            "Gate 11 does not measure I/O latency\n"
            "See docs/admin-runbook.md\n"
        )
        errors = vpl.check_forbidden_paths(public_tree)
        assert any("stale Gate 11" in e for e in errors)

    def test_yaml_comment_is_ok(self, public_tree):
        alerts = public_tree / "alerts"
        alerts.mkdir()
        (alerts / "bsod-risk-prometheusrules.yaml").write_text(
            "# see docs/operator-runbook.md internally\n"
            "alert: Foo\n"
        )
        errors = vpl.check_forbidden_paths(public_tree)
        assert errors == []

    def test_analyze_py_in_alert_yaml_fails(self, public_tree):
        alerts = public_tree / "alerts"
        alerts.mkdir()
        (alerts / "bsod-risk-prometheusrules.yaml").write_text(
            "python3 insights-rules/analyze.py --input foo\n"
        )
        errors = vpl.check_forbidden_paths(public_tree)
        assert any("insights-rules" in e for e in errors)


class TestMarkdownLinks:
    def test_404_relative_link_fails(self, public_tree):
        (public_tree / "README.md").write_text(
            "See [missing](docs/nope.md) and "
            "[docs/admin-runbook.md](docs/admin-runbook.md).\n"
        )
        errors = vpl.check_markdown_links(public_tree)
        assert any("404" in e and "nope.md" in e for e in errors)

    def test_http_and_anchor_ok(self, public_tree):
        (public_tree / "README.md").write_text(
            "[kcs](https://access.redhat.com/solutions/7129390) "
            "[here](#gate-checks) "
            "[runbook](docs/admin-runbook.md)\n"
        )
        errors = vpl.check_markdown_links(public_tree)
        assert errors == []


class TestGateScriptCustomerStrings:
    def test_next_steps_analyze_py_fails(self, public_tree):
        (public_tree / "scripts" / "cnv-win-bsod-audit.sh").write_text(
            'echo " Python analyzer (insights-rules/analyze.py) for coverage"\n'
        )
        errors = vpl.check_gate_script_customer_strings(public_tree)
        assert errors
        assert all(not e.startswith("#") for e in errors)

    def test_comment_only_is_ok(self, public_tree):
        (public_tree / "scripts" / "cnv-win-bsod-audit.sh").write_text(
            "# see insights-rules/analyze.py for the Python counterpart\n"
            "echo ok\n"
        )
        errors = vpl.check_gate_script_customer_strings(public_tree)
        assert errors == []
