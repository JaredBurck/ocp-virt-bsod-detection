"""Regression tests for scripts/ci/validate-metric-names.py.

R-46 (Wave 7, Recommendation 6): this validator existed with no test coverage
of its own, matching this repo's near-universal validator-plus-test
convention gap the follow-up review flagged. These tests exercise `main()`
against a synthetic repo skeleton (REPO_ROOT and SCAN_FILES monkeypatched to
a pytest tmp_path) so a change to the allowlist or the scanning regex that
silently stops catching real drift -- the exact class this validator guards
against in its own module docstring (the `windows_pagefile_usage_bytes`
fabricated-metric-name bug it was written to prevent) -- would be caught
here rather than only in production.
"""
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-metric-names.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_metric_names", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vmn = _load_module()


def _write(root, rel_path, content):
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """Empty repo skeleton; SCAN_FILES is monkeypatched to a single synthetic
    file so tests never touch the real shipped alert/dashboard/doc sources."""
    monkeypatch.setattr(vmn, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(vmn, "SCAN_FILES", ["fixture.yaml"])
    return tmp_path


class TestAllowlistedMetricsPass:
    def test_known_metric_passes(self, fake_repo):
        _write(fake_repo, "fixture.yaml", "expr: windows_logical_disk_read_seconds_total\n")
        assert vmn.main() == 0

    def test_cpu_collector_metric_passes(self, fake_repo):
        """R-46: windows_cpu_time_total (verified against upstream
        docs/collector.cpu.md) must be recognised now that a consumer
        references it."""
        _write(fake_repo, "fixture.yaml", 'expr: windows_cpu_time_total{mode="idle"}\n')
        assert vmn.main() == 0

    def test_memory_collector_metrics_pass(self, fake_repo):
        """R-46: windows_memory_physical_free_bytes/_total_bytes (verified
        against upstream docs/collector.memory.md)."""
        _write(fake_repo, "fixture.yaml",
               "expr: windows_memory_physical_free_bytes / windows_memory_physical_total_bytes\n")
        assert vmn.main() == 0

    def test_generic_windows_exporter_prose_mention_ignored(self, fake_repo):
        """The literal token 'windows_exporter' itself is prose, not a
        metric name, and must never be flagged."""
        _write(fake_repo, "fixture.yaml", "Deploy windows_exporter with the cpu collector enabled.\n")
        assert vmn.main() == 0


class TestUnknownMetricFails:
    def test_fabricated_metric_name_fails(self, fake_repo):
        """Reproduces the exact v0.7.0 regression this validator exists to
        catch: a plausible-sounding but non-existent metric name."""
        _write(fake_repo, "fixture.yaml", "expr: windows_pagefile_usage_bytes > 90\n")
        assert vmn.main() == 1

    def test_truncated_metric_family_reference_fails(self, fake_repo):
        """A comment referencing a metric FAMILY with a trailing wildcard
        (e.g. 'windows_cpu_*') tokenises to 'windows_cpu_', which is not a
        real metric name either -- this must fail, not be silently treated
        as a family-level allowlist entry. Guards the exact mistake this
        validator's own test author made while authoring R-46 (fixed in the
        same commit that added this test)."""
        _write(fake_repo, "fixture.yaml", "# nothing downstream consumed windows_cpu_* before this\n")
        assert vmn.main() == 1

    def test_only_the_first_occurrence_per_file_is_reported(self, fake_repo):
        """seen_unknown dedup: the same bad token twice in one file should
        not multiply the failure count, but main() must still return 1."""
        _write(fake_repo, "fixture.yaml",
               "expr: windows_bogus_metric_total\nexpr2: windows_bogus_metric_total\n")
        assert vmn.main() == 1


class TestEvidenceCompletenessMetricNameCheck:
    """Issue K (coordinated with R-27): check_evidence_completeness_metric_name()
    -- the self-consistency check added in place of the originally-proposed
    windows_exporter-style allowlist entry (rejected: bsod_vm_checks_assessed/
    _total have no external upstream source of truth to allowlist against;
    this framework both defines and consumes them, so the real risk is the
    exporter script and the recording rule drifting from each other, not
    either one drifting from an upstream doc)."""

    GOOD_EXPORTER = (
        'echo "# TYPE bsod_evidence_completeness_percent gauge"\n'
        'echo "# TYPE bsod_vm_checks_assessed gauge"\n'
        'echo "# TYPE bsod_vm_checks_total gauge"\n'
    )
    GOOD_RECORDING_RULE = (
        "expr: sum(bsod_vm_checks_assessed) / sum(bsod_vm_checks_total)\n"
    )

    def _write_all(self, root, exporter_text, recording_rule_text):
        _write(root, "scripts/cnv-bsod-fleet-exporter.sh", exporter_text)
        _write(root, "alerts/bsod-risk-recording-rules.yaml", recording_rule_text)

    def test_consistent_names_pass(self, fake_repo):
        self._write_all(fake_repo, self.GOOD_EXPORTER, self.GOOD_RECORDING_RULE)
        assert vmn.check_evidence_completeness_metric_name() == 0

    def test_missing_files_return_zero_not_a_failure(self, fake_repo):
        """Neither file exists in this fixture repo -- must not be treated
        as a drift; only main()'s allowlist scan applies to a repo skeleton
        that doesn't ship the exporter at all."""
        assert vmn.check_evidence_completeness_metric_name() == 0

    def test_missing_convenience_gauge_type_line_fails(self, fake_repo):
        exporter_text = (
            'echo "# TYPE bsod_vm_checks_assessed gauge"\n'
            'echo "# TYPE bsod_vm_checks_total gauge"\n'
        )
        self._write_all(fake_repo, exporter_text, self.GOOD_RECORDING_RULE)
        assert vmn.check_evidence_completeness_metric_name() == 1

    def test_missing_raw_counter_type_line_fails(self, fake_repo):
        """Reproduces the exact drift class this check exists for: the
        exporter renamed/dropped bsod_vm_checks_total but the recording rule
        was not updated to match."""
        exporter_text = (
            'echo "# TYPE bsod_evidence_completeness_percent gauge"\n'
            'echo "# TYPE bsod_vm_checks_assessed gauge"\n'
        )
        self._write_all(fake_repo, exporter_text, self.GOOD_RECORDING_RULE)
        assert vmn.check_evidence_completeness_metric_name() == 1

    def test_recording_rule_not_referencing_emitted_metric_fails(self, fake_repo):
        """The exporter emits bsod_vm_checks_total correctly, but the
        recording rule's expr was edited to query a different (typo'd or
        stale) name -- the round-trip drift this check is actually for."""
        recording_rule_text = "expr: sum(bsod_vm_checks_assessed) / sum(bsod_vm_checks_grand_total)\n"
        self._write_all(fake_repo, self.GOOD_EXPORTER, recording_rule_text)
        assert vmn.check_evidence_completeness_metric_name() == 1


class TestScanFilesScoping:
    def test_files_outside_scan_files_are_not_checked(self, fake_repo):
        """A bad metric name in a file NOT in SCAN_FILES must not be picked
        up -- proves the scoping is real, not accidentally scanning the
        whole tree."""
        _write(fake_repo, "not-scanned.yaml", "expr: windows_totally_made_up_metric\n")
        assert vmn.main() == 0

    def test_missing_scan_file_is_skipped_not_flagged(self, fake_repo):
        """A repo skeleton missing the one file in SCAN_FILES (as this
        fixture always is unless a test writes it) must not itself be a
        failure."""
        assert vmn.main() == 0


class TestPlatformMetricAllowlist:
    """v0.26.0: KubeVirt / cAdvisor / node_exporter metric names.

    Until v0.26.0 this validator covered `windows_*` only, and the two
    hypervisor alert CRs were not even scanned -- so a typo'd or renamed
    platform metric shipped silently: the expression matched nothing, the rule
    never fired, and promtool did not object because the PromQL was still
    syntactically valid. Same failure shape as peer-review F-01/F-02, both of
    which were found by hand.
    """

    def test_every_shipped_platform_metric_is_allowlisted(self):
        """The real CRs must pass -- this is the seed correctness check."""
        assert vmn.main() == 0

    def test_allowlist_covers_both_storage_directions(self):
        """F-01: read and write counters must both be recognised.

        If only the read names were allowlisted, adding the write path would
        fail CI for the wrong reason and invite someone to weaken the check.
        """
        for direction in ("read", "write"):
            assert f"kubevirt_vmi_storage_{direction}_times_seconds_total" in \
                vmn.ALLOWED_PLATFORM_METRICS
            assert f"kubevirt_vmi_storage_iops_{direction}_total" in \
                vmn.ALLOWED_PLATFORM_METRICS

    def test_psi_metric_is_allowlisted(self):
        """F-02: the PSI signal that replaced the CFS-based contention alert."""
        assert "node_pressure_cpu_waiting_seconds_total" in \
            vmn.ALLOWED_PLATFORM_METRICS

    def test_token_regex_matches_the_prefixes_we_care_about(self):
        expr = ("rate(kubevirt_vmi_storage_iops_read_total[5m]) + "
                "container_cpu_cfs_periods_total + "
                "node_pressure_cpu_waiting_seconds_total + kube_node_labels")
        assert set(vmn.PLATFORM_TOKEN_RE.findall(expr)) == {
            "kubevirt_vmi_storage_iops_read_total",
            "container_cpu_cfs_periods_total",
            "node_pressure_cpu_waiting_seconds_total",
            "kube_node_labels",
        }

    def test_token_regex_ignores_unrelated_identifiers(self):
        """Must not claim `windows_*` (handled by the other allowlist) or
        this framework's own `bsod_*` / `bsod:` series."""
        expr = ("windows_cpu_time_total + bsod_virtio_driver_outdated + "
                "bsod:vmi_disk_latency:worst_1h")
        assert vmn.PLATFORM_TOKEN_RE.findall(expr) == []

    def test_typo_in_a_metric_name_is_caught(self, tmp_path, monkeypatch):
        """The whole point: a one-character slip must fail CI, not ship."""
        cr = tmp_path / "alerts" / "bad.yaml"
        cr.parent.mkdir(parents=True)
        cr.write_text(
            "spec:\n"
            "  groups:\n"
            "    - name: g\n"
            "      rules:\n"
            "        - alert: Typo\n"
            "          expr: kubevirt_vmi_storage_iops_raed_total > 0\n")
        monkeypatch.setattr(vmn, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(vmn, "PLATFORM_SCAN_FILES", ["alerts/bad.yaml"])
        monkeypatch.setattr(vmn, "SCAN_FILES", [])
        monkeypatch.setattr(vmn, "check_evidence_completeness_metric_name",
                            lambda: 0)
        assert vmn.main() == 1

    def test_prose_in_annotations_is_not_flagged(self, tmp_path, monkeypatch):
        """Only `expr:` is executable.

        The alert CRs carry long `prerequisite:`/`calibration_status:` prose
        that legitimately names metrics -- including a `grep node_pressure_cpu`
        verification command. Flagging documentation would train reviewers to
        ignore this check, which is worse than not having it.
        """
        cr = tmp_path / "alerts" / "prose.yaml"
        cr.parent.mkdir(parents=True)
        cr.write_text(
            "spec:\n"
            "  groups:\n"
            "    - name: g\n"
            "      rules:\n"
            "        - alert: Fine\n"
            "          annotations:\n"
            "            prerequisite: |\n"
            "              verify with: grep kubevirt_vmi_totally_made_up\n"
            "          expr: kube_node_labels > 0\n")
        monkeypatch.setattr(vmn, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(vmn, "PLATFORM_SCAN_FILES", ["alerts/prose.yaml"])
        monkeypatch.setattr(vmn, "SCAN_FILES", [])
        monkeypatch.setattr(vmn, "check_evidence_completeness_metric_name",
                            lambda: 0)
        assert vmn.main() == 0

