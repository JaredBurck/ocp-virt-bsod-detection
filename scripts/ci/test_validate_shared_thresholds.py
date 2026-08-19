"""Regression tests for scripts/ci/validate-shared-thresholds.py.

N22 (v0.15.0 Phase 6): this validator exists specifically to prevent the
class of magic-number drift documented in its own module docstring (M-7's
IoTimeoutValue existing as four uncoordinated literals), but had no test
coverage of its own -- a change to one of its check functions (e.g. a regex
that stops matching after an alert expression is reformatted, silently
turning "FAIL on drift" into "always pass" because the pattern simply never
matches and the function returns early) would go unnoticed by CI. These
tests exercise each check function against a synthetic repo skeleton
(REPO_ROOT monkeypatched to a pytest tmp_path) with a matching threshold
(expect no failures) and a deliberately-drifted one (expect FAILURES to
catch it), mirroring the test_validate_dashboard_configmap.py /
test_validate_acm_policy.py pattern already used for this CI script family.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-shared-thresholds.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_shared_thresholds", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vst = _load_module()


def _write(root, rel_path, content):
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """Empty repo skeleton; each test writes only the files its check reads.

    REPO_ROOT and the module-level FAILURES accumulator are both
    monkeypatched so tests never touch the real repo and never leak
    failures between cases (each check function appends to the same
    module-level list rather than returning one).
    """
    monkeypatch.setattr(vst, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(vst, "FAILURES", [])
    return tmp_path


class TestCheckIoTimeoutRecordingRule:
    def test_matching_threshold_passes(self, fake_repo):
        _write(fake_repo, "shared/io-timeout-thresholds.json",
               json.dumps({"risk_factor_at_or_below_seconds": 60}))
        _write(fake_repo, "alerts/bsod-risk-recording-rules.yaml",
               "expr: min by (vm_name) (bsod_io_timeout_value) <= bool 60\n"
               "# kubevirt_vmi_storage_read_times_seconds_total\n"
               "# kubevirt_vmi_storage_iops_read_total\n"
               "# kubevirt_vmi_storage_write_times_seconds_total\n"
               "# kubevirt_vmi_storage_iops_write_total\n")
        vst.check_io_timeout_recording_rule()
        assert vst.FAILURES == []

    def test_drifted_threshold_fails(self, fake_repo):
        """Reproduces M-7's exact regression class: the recording rule's
        literal (300, an old PowerShell-remediation value) no longer matches
        the shared config (60)."""
        _write(fake_repo, "shared/io-timeout-thresholds.json",
               json.dumps({"risk_factor_at_or_below_seconds": 60}))
        _write(fake_repo, "alerts/bsod-risk-recording-rules.yaml",
               "expr: min by (vm_name) (bsod_io_timeout_value) <= bool 300\n")
        vst.check_io_timeout_recording_rule()
        assert len(vst.FAILURES) == 1
        assert "IoTimeoutValue" in vst.FAILURES[0]
        assert "300" in vst.FAILURES[0] and "60" in vst.FAILURES[0]

    def test_missing_expression_flags_checker_itself(self, fake_repo):
        """If the alert is restructured so the checker's own regex no longer
        matches anything, that must surface as a FAILURE (fail-loud), not a
        silent no-op pass."""
        _write(fake_repo, "shared/io-timeout-thresholds.json",
               json.dumps({"risk_factor_at_or_below_seconds": 60}))
        _write(fake_repo, "alerts/bsod-risk-recording-rules.yaml", "# rewritten, no match\n")
        vst.check_io_timeout_recording_rule()
        assert len(vst.FAILURES) == 1
        assert "could not find" in vst.FAILURES[0]

    def test_missing_shared_config_flags_failure(self, fake_repo):
        _write(fake_repo, "alerts/bsod-risk-recording-rules.yaml",
               "expr: min by (vm_name) (bsod_io_timeout_value) <= bool 60\n"
               "# kubevirt_vmi_storage_read_times_seconds_total\n"
               "# kubevirt_vmi_storage_iops_read_total\n"
               "# kubevirt_vmi_storage_write_times_seconds_total\n"
               "# kubevirt_vmi_storage_iops_write_total\n")
        vst.check_io_timeout_recording_rule()
        assert any("missing shared config" in f for f in vst.FAILURES)


class TestCheckStorageLatencyAlerts:
    RULES_TEMPLATE = (
        "        - alert: BSODRisk_StorageLatencyElevated\n"
        "          expr: |\n"
        "            bsod:vmi_disk_latency:worst_1h >= {warn}\n"
        "          for: 15m\n"
        "        - alert: BSODRisk_StorageLatencyHigh\n"
        "          expr: |\n"
        "            bsod:vmi_disk_latency:worst_1h >= {crit}\n"
        "          for: 10m\n"
        "        - alert: BSODRisk_StorageLatencyBurst\n"
        "          expr: |\n"
        "            max_over_time(\n"
        "              (\n"
        "                foo\n"
        "              )[1h:5m]\n"
        "            ) >= {burst}\n"
        "        - alert: BSODRisk_StorageLatencyTrending\n"
        "          expr: |\n"
        "            bsod:vmi_disk_latency:worst_1h >= {warn}\n"
        "            and\n"
        "            (bsod:vmi_disk_latency:worst_24h) > {trend}\n"
    )
    GUEST_TEMPLATE = (
        "        - alert: BSODRisk_GuestDiskLatencyHigh\n"
        "          expr: |\n"
        "            (\n"
        "              foo\n"
        "            ) >= {guest_crit}\n"
        "          for: 10m\n"
    )

    def _write_all(self, root, warn, crit, burst, trend, guest_crit):
        cfg = {
            "sustained_warn_seconds": warn,
            "sustained_critical_seconds": crit,
            "burst_seconds": burst,
            "trend_ratio": trend,
        }
        _write(root, "shared/storage-latency-thresholds.json", json.dumps(cfg))
        _write(root, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(warn=warn, crit=crit, burst=burst, trend=trend))
        _write(root, "alerts/bsod-risk-guest-alerts.yaml",
               self.GUEST_TEMPLATE.format(guest_crit=guest_crit))

    def test_matching_thresholds_pass(self, fake_repo):
        self._write_all(fake_repo, warn=0.5, crit=1.0, burst=5, trend=1.5, guest_crit=1.0)
        vst.check_storage_latency_alerts()
        assert vst.FAILURES == []

    def test_drifted_sustained_warn_fails(self, fake_repo):
        """Reproduces H-5's exact regression class: an alert expression
        (here, the 0.5s warn threshold reverting to the old 30s/op value)
        drifts from its shared/storage-latency-thresholds.json source of
        truth."""
        self._write_all(fake_repo, warn=0.5, crit=1.0, burst=5, trend=1.5, guest_crit=1.0)
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(warn=30, crit=1.0, burst=5, trend=1.5))
        vst.check_storage_latency_alerts()
        elevated_failures = [f for f in vst.FAILURES if "BSODRisk_StorageLatencyElevated" in f]
        assert len(elevated_failures) == 1
        assert "drift" in elevated_failures[0]

    def test_drifted_burst_threshold_fails(self, fake_repo):
        self._write_all(fake_repo, warn=0.5, crit=1.0, burst=5, trend=1.5, guest_crit=1.0)
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(warn=0.5, crit=1.0, burst=10, trend=1.5))
        vst.check_storage_latency_alerts()
        assert any("BSODRisk_StorageLatencyBurst" in f and "drift" in f for f in vst.FAILURES)

    def test_drifted_guest_threshold_fails(self, fake_repo):
        self._write_all(fake_repo, warn=0.5, crit=1.0, burst=5, trend=1.5, guest_crit=1.0)
        _write(fake_repo, "alerts/bsod-risk-guest-alerts.yaml",
               self.GUEST_TEMPLATE.format(guest_crit=2.0))
        vst.check_storage_latency_alerts()
        assert any("BSODRisk_GuestDiskLatencyHigh" in f and "drift" in f for f in vst.FAILURES)

    def test_threshold_is_read_from_its_own_alert_not_a_neighbour(self, fake_repo):
        """F-01 regression: patterns must anchor on the alert, not on `for:`.

        The pre-v0.26.0 checker disambiguated two identical-looking
        `avg_1h >= N` expressions purely by the `for:` duration that followed,
        and `re.search` scans the WHOLE file. Here Elevated and High are given
        DIFFERENT thresholds but the SAME `for: 15m`, which under the old
        patterns made High's lookup match Elevated's expression and report a
        spurious drift (or mask a real one). Anchoring on `- alert: <Name>`
        makes each lookup structurally incapable of reading a neighbour.
        """
        cfg = {
            "sustained_warn_seconds": 0.5,
            "sustained_critical_seconds": 1.0,
            "burst_seconds": 5,
            "trend_ratio": 1.5,
        }
        _write(fake_repo, "shared/storage-latency-thresholds.json", json.dumps(cfg))
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               "        - alert: BSODRisk_StorageLatencyElevated\n"
               "          expr: |\n"
               "            bsod:vmi_disk_latency:worst_1h >= 0.5\n"
               "          for: 15m\n"
               "        - alert: BSODRisk_StorageLatencyHigh\n"
               "          expr: |\n"
               "            bsod:vmi_disk_latency:worst_1h >= 1.0\n"
               "          for: 15m\n"          # deliberately the SAME duration
               "        - alert: BSODRisk_StorageLatencyBurst\n"
               "          expr: |\n"
               "            max_over_time(\n"
               "              (foo)[1h:5m]\n"
               "            ) >= 5\n"
               "        - alert: BSODRisk_StorageLatencyTrending\n"
               "          expr: |\n"
               "            bsod:vmi_disk_latency:worst_1h >= 0.5\n"
               "            and\n"
               "            (bsod:vmi_disk_latency:worst_24h) > 1.5\n")
        _write(fake_repo, "alerts/bsod-risk-guest-alerts.yaml",
               self.GUEST_TEMPLATE.format(guest_crit=1.0))
        vst.check_storage_latency_alerts()
        assert vst.FAILURES == []

    def test_missing_alert_is_reported_not_silently_skipped(self, fake_repo):
        """A guard that cannot find its target must fail loudly.

        Returning None from the block extractor and moving on would turn this
        checker into a no-op the moment an alert is renamed -- the quiet
        failure mode that lets a threshold drift unnoticed.
        """
        cfg = {"sustained_warn_seconds": 0.5, "sustained_critical_seconds": 1.0,
               "burst_seconds": 5, "trend_ratio": 1.5}
        _write(fake_repo, "shared/storage-latency-thresholds.json", json.dumps(cfg))
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               "        - alert: BSODRisk_SomethingElseEntirely\n"
               "          expr: |\n"
               "            foo >= 0.5\n")
        _write(fake_repo, "alerts/bsod-risk-guest-alerts.yaml",
               self.GUEST_TEMPLATE.format(guest_crit=1.0))
        vst.check_storage_latency_alerts()
        assert any("BSODRisk_StorageLatencyElevated" in f and "could not locate" in f
                   for f in vst.FAILURES)

    def test_drifted_trend_ratio_fails(self, fake_repo):
        self._write_all(fake_repo, warn=0.5, crit=1.0, burst=5, trend=1.5, guest_crit=1.0)
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(warn=0.5, crit=1.0, burst=5, trend=2.0))
        vst.check_storage_latency_alerts()
        assert any("StorageLatencyTrending" in f and "drift" in f for f in vst.FAILURES)


class TestCheckHostCPUContentionAlert:
    """CPU-contention threshold bindings (R-45/N-07, split under F-02).

    v0.26.0 split one alert into two: BSODRisk_VirtLauncherCPUThrottled keeps
    the CFS expression under an honest name, and BSODRisk_HostCPUContention
    measures real node contention via /proc/schedstat run-queue wait so it can
    fire on a default cluster (no CPU limits, hence no CFS quota, hence
    flat-zero counters).

    BOTH expressions contain a `> 0` guard alongside their real threshold --
    the CFS one guards its denominator, the run-queue one guards its scoping
    join. That is why the checker matches the configured value against the SET
    of comparisons in the block rather than by position: first-match reads the
    guard on one alert and the threshold on the other, last-match inverts it.
    """

    RULES_TEMPLATE = (
        "        - alert: BSODRisk_VirtLauncherCPUThrottled\n"
        "          expr: |\n"
        "            (\n"
        "              sum by (node) (rate(container_cpu_cfs_throttled_periods_total{{pod=~\"virt-launcher-.*\"}}[5m]))\n"
        "              /\n"
        "              sum by (node) (rate(container_cpu_cfs_periods_total{{pod=~\"virt-launcher-.*\"}}[5m]))\n"
        "            ) > {throttle}\n"
        "            and on(node)\n"
        "            sum by (node) (rate(container_cpu_cfs_periods_total{{pod=~\"virt-launcher-.*\"}}[5m])) > 0\n"
        "          for: 10m\n"
        "        - alert: BSODRisk_HostCPUContention\n"
        "          expr: |\n"
        "            avg by (instance) (rate(node_schedstat_waiting_seconds_total[5m]))\n"
        "            * on(instance) group_left()\n"
        "            (\n"
        "              count by (instance) (\n"
        "                label_replace(kube_node_labels{{label_cpu_vendor_node_kubevirt_io_intel=\"true\"}}, \"instance\", \"$1\", \"node\", \"(.*)\")\n"
        "              ) > 0\n"
        "            ) > {runq}\n"
        "          for: 10m\n"
    )

    def _write_all(self, root, throttle, runq=None):
        runq = throttle if runq is None else runq
        _write(root, "shared/host-contention-thresholds.json",
               json.dumps({"throttle_ratio_warn": throttle,
                           "runqueue_wait_per_cpu_warn": runq}))
        _write(root, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(throttle=throttle, runq=runq))

    def test_matching_thresholds_pass(self, fake_repo):
        self._write_all(fake_repo, 0.25, 1.0)
        vst.check_host_cpu_contention_alert()
        assert vst.FAILURES == []

    def test_drifted_throttle_threshold_fails(self, fake_repo):
        self._write_all(fake_repo, 0.25, 1.0)
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(throttle=0.30, runq=1.0))
        vst.check_host_cpu_contention_alert()
        assert len(vst.FAILURES) == 1
        assert "BSODRisk_VirtLauncherCPUThrottled" in vst.FAILURES[0]

    def test_drifted_runqueue_threshold_fails(self, fake_repo):
        """The run-queue alert must be bound independently of the CFS one."""
        self._write_all(fake_repo, 0.25, 1.0)
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(throttle=0.25, runq=2.0))
        vst.check_host_cpu_contention_alert()
        assert len(vst.FAILURES) == 1
        assert "BSODRisk_HostCPUContention" in vst.FAILURES[0]

    def test_guard_constant_is_not_mistaken_for_the_threshold(self, fake_repo):
        """Both exprs contain a `> 0` guard.

        A positional match would bind that zero instead of the real threshold
        and report a spurious drift -- or, worse, silently validate the guard
        and let the threshold rot.
        """
        self._write_all(fake_repo, 0.25, 1.0)
        vst.check_host_cpu_contention_alert()
        assert not any("compares against" in f for f in vst.FAILURES)

    def test_each_alert_reads_its_own_threshold(self, fake_repo):
        """The two alerts sit adjacent; distinct values make cross-reads visible."""
        self._write_all(fake_repo, throttle=0.25, runq=3.5)
        vst.check_host_cpu_contention_alert()
        assert vst.FAILURES == []

    def test_missing_expression_flags_checker_itself(self, fake_repo):
        _write(fake_repo, "shared/host-contention-thresholds.json",
               json.dumps({"throttle_ratio_warn": 0.25,
                           "runqueue_wait_per_cpu_warn": 1.0}))
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml", "# rewritten, no match\n")
        vst.check_host_cpu_contention_alert()
        assert len(vst.FAILURES) == 2
        assert all("could not find" in f for f in vst.FAILURES)

    def test_missing_runqueue_key_is_reported(self, fake_repo):
        """A renamed/removed shared key must fail loudly, not skip the check.

        This is not hypothetical: the key WAS renamed once, when the alert was
        rebased off PSI onto run-queue wait after PSI proved absent on the
        live validation cluster.
        """
        _write(fake_repo, "shared/host-contention-thresholds.json",
               json.dumps({"throttle_ratio_warn": 0.25}))
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(throttle=0.25, runq=1.0))
        vst.check_host_cpu_contention_alert()
        assert any("runqueue_wait_per_cpu_warn" in f for f in vst.FAILURES)

    def test_missing_shared_config_flags_failure(self, fake_repo):
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(throttle=0.25, runq=1.0))
        vst.check_host_cpu_contention_alert()
        assert any("missing shared config" in f for f in vst.FAILURES)


class TestCheckEvidenceCompletenessAlert:
    """Issue K (coordinated with R-27): BSODRisk_FleetEvidenceIncomplete's
    fleet_warn_below_pct binding. The shared config is a 0-100 percent (human
    readability); the recording rule it binds to is a checks-weighted 0-1
    ratio (sum(bsod_vm_checks_assessed)/sum(bsod_vm_checks_total)), so the
    alert literal is expected to be fleet_warn_below_pct / 100, not the bare
    percent -- this is the one binding in this file with a unit conversion,
    not a 1:1 literal match, so it gets its own dedicated drift test."""

    RULES_TEMPLATE = (
        "        - alert: BSODRisk_FleetEvidenceIncomplete\n"
        "          expr: bsod:fleet_evidence_completeness:ratio < {ratio}\n"
        "          for: 30m\n"
    )

    def _write_all(self, root, fleet_warn_below_pct):
        _write(root, "shared/evidence-completeness-thresholds.json",
               json.dumps({"fleet_warn_below_pct": fleet_warn_below_pct}))
        _write(root, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(ratio=fleet_warn_below_pct / 100.0))

    def test_matching_threshold_passes(self, fake_repo):
        self._write_all(fake_repo, 80)
        vst.check_evidence_completeness_alert()
        assert vst.FAILURES == []

    def test_drifted_threshold_fails(self, fake_repo):
        self._write_all(fake_repo, 80)
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(ratio=0.70))
        vst.check_evidence_completeness_alert()
        assert len(vst.FAILURES) == 1
        assert "BSODRisk_FleetEvidenceIncomplete" in vst.FAILURES[0]

    def test_bare_percent_instead_of_ratio_fails(self, fake_repo):
        """Regression guard for the exact unit-mismatch bug this checker
        exists to catch: someone reverts the alert expression back to the
        old bare-percent literal (80) instead of the ratio (0.8)."""
        _write(fake_repo, "shared/evidence-completeness-thresholds.json",
               json.dumps({"fleet_warn_below_pct": 80}))
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(ratio=80))
        vst.check_evidence_completeness_alert()
        assert len(vst.FAILURES) == 1
        assert "BSODRisk_FleetEvidenceIncomplete" in vst.FAILURES[0]

    def test_missing_shared_config_reports_missing_config_only(self, fake_repo):
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml",
               self.RULES_TEMPLATE.format(ratio=0.8))
        vst.check_evidence_completeness_alert()
        assert len(vst.FAILURES) == 1
        assert "missing shared config" in vst.FAILURES[0]

    def test_missing_alert_expression_fails_with_actionable_message(self, fake_repo):
        self._write_all(fake_repo, 80)
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml", "groups: []\n")
        vst.check_evidence_completeness_alert()
        assert len(vst.FAILURES) == 1
        assert "could not find" in vst.FAILURES[0]


class TestCheckRiskScoringX100Parity:
    def _write_cfg(self, root, domain_weights, domain_weights_x100):
        cfg = {
            "severity_weights": {"FAIL": 1.0}, "severity_weights_x100": {"FAIL": 100},
            "domain_weights": domain_weights, "domain_weights_x100": domain_weights_x100,
            "confidence_multipliers": {"KCS-VALIDATED": 1.0},
            "confidence_multipliers_x100": {"KCS-VALIDATED": 100},
            "tier_thresholds": {"high": 7.0}, "tier_thresholds_x100": {"high": 700},
        }
        _write(root, "shared/risk-scoring.json", json.dumps(cfg))

    def test_matching_x100_values_pass(self, fake_repo):
        self._write_cfg(fake_repo, {"crash": 3.0}, {"crash": 300})
        vst.check_risk_scoring_x100_parity()
        assert vst.FAILURES == []

    def test_drifted_x100_value_fails(self, fake_repo):
        self._write_cfg(fake_repo, {"crash": 3.0}, {"crash": 250})
        vst.check_risk_scoring_x100_parity()
        assert len(vst.FAILURES) == 1
        assert "domain_weights.crash" in vst.FAILURES[0]

    def test_mismatched_keys_fail(self, fake_repo):
        self._write_cfg(fake_repo, {"crash": 3.0}, {"storage": 300})
        vst.check_risk_scoring_x100_parity()
        assert any("different keys" in f for f in vst.FAILURES)


class TestCheckGateDomainsComplete:
    def _write_cfg_and_audit(self, root, gate_domains, domain_weights, gate_numbers):
        cfg = {"gate_domains": gate_domains, "domain_weights": domain_weights}
        _write(root, "shared/risk-scoring.json", json.dumps(cfg))
        audit_src = "\n".join(f'  set_gate {n} "" ""' for n in gate_numbers)
        _write(root, "scripts/cnv-win-bsod-audit.sh", audit_src)

    def test_every_gate_mapped_passes(self, fake_repo):
        self._write_cfg_and_audit(
            fake_repo, {"1": "storage", "2": "cpu"}, {"storage": 1.0, "cpu": 2.0}, [1, 2])
        vst.check_gate_domains_complete()
        assert vst.FAILURES == []

    def test_new_unmapped_gate_fails(self, fake_repo):
        """Reproduces adding a new gate (e.g. a future Gate 21) to the audit
        script without registering it in shared/risk-scoring.json's
        gate_domains -- it would otherwise silently fall back to 'config'."""
        self._write_cfg_and_audit(
            fake_repo, {"1": "storage"}, {"storage": 1.0}, [1, 21])
        vst.check_gate_domains_complete()
        assert len(vst.FAILURES) == 1
        assert "21" in vst.FAILURES[0]

    def test_domain_with_no_weight_fails(self, fake_repo):
        self._write_cfg_and_audit(
            fake_repo, {"1": "nonexistent-domain"}, {"storage": 1.0}, [1])
        vst.check_gate_domains_complete()
        assert any("no weight" in f for f in vst.FAILURES)


class TestCheckFailUpwardDefaultsMatch:
    def _write_scripts(self, root, bash_domain_default, python_domain_default,
                        bash_conf_default, python_conf_default):
        bash_src = (
            'rs_score_finding() {\n'
            '  local gate="$1"\n'
            f'  local domain="${{RS_GATE_DOMAIN[$gate]:-{bash_domain_default}}}"\n'
            '  local conf_name="$2"\n'
            f'  local conf="${{RS_CONFIDENCE[$conf_name]:-${{RS_CONFIDENCE[{bash_conf_default}]:-100}}}}"\n'
            '}\n'
        )
        _write(root, "scripts/lib/risk-scoring.sh", bash_src)

        python_src = (
            "def score_finding(result):\n"
            f'    domain_weight = DOMAIN_WEIGHTS.get(domain, DOMAIN_WEIGHTS.get("{python_domain_default}", 3.0))\n'
            "    confidence_mult = CONFIDENCE_MULTIPLIERS.get(\n"
            f'        result.confidence, CONFIDENCE_MULTIPLIERS.get("{python_conf_default}", 1.0))\n'
        )
        _write(root, "insights-rules/plugins/risk_scoring.py", python_src)

    def test_correct_fail_upward_defaults_pass(self, fake_repo):
        self._write_scripts(fake_repo, "crash", "crash", "KCS-VALIDATED", "KCS-VALIDATED")
        vst.check_fail_upward_defaults_match()
        assert vst.FAILURES == []

    def test_bash_domain_default_drifted_low_fails(self, fake_repo):
        """Reproduces N15's exact bug: an unmapped domain silently falling
        back to the LOWEST-weighted domain instead of failing upward."""
        self._write_scripts(fake_repo, "config", "crash", "KCS-VALIDATED", "KCS-VALIDATED")
        vst.check_fail_upward_defaults_match()
        assert any("'config'" in f and "risk-scoring.sh" in f for f in vst.FAILURES)

    def test_python_confidence_default_drifted_fails(self, fake_repo):
        self._write_scripts(fake_repo, "crash", "crash", "KCS-VALIDATED", "UNVALIDATED")
        vst.check_fail_upward_defaults_match()
        assert any("'UNVALIDATED'" in f and "risk_scoring.py" in f for f in vst.FAILURES)

    def test_layers_disagreeing_both_fail(self, fake_repo):
        self._write_scripts(fake_repo, "storage", "crash", "KCS-VALIDATED", "KCS-VALIDATED")
        vst.check_fail_upward_defaults_match()
        assert any("'storage'" in f for f in vst.FAILURES)


class TestCheckCalibrationStatusDrift:
    """#3 (v0.16.0): the calibration-status sweep guard."""

    STALE_LINE = (
        "thresholds calibration outstanding, see below\n"
    )
    CURRENT_LINE = (
        "thresholds calibration PARTIAL, see below\n"
    )

    def _write_cfg(self, root, calibration_status):
        _write(root, "shared/storage-latency-thresholds.json",
               json.dumps({"_calibration_status": calibration_status}))

    def test_still_outstanding_at_source_allows_siblings_to_say_so(self, fake_repo):
        """While the JSON itself still says OUTSTANDING, siblings repeating
        that are accurate, not stale -- must not be flagged."""
        self._write_cfg(fake_repo, "OUTSTANDING")
        _write(fake_repo, "alerts/README.md", self.STALE_LINE)
        vst.check_calibration_status_drift()
        assert vst.FAILURES == []

    def test_source_moved_on_but_sibling_still_says_outstanding_fails(self, fake_repo):
        """Reproduces #3's exact regression: the JSON source of truth moved
        to PARTIAL (a real 2026-07-29 calibration run), but a shipped
        alert/doc file was never updated to match."""
        self._write_cfg(fake_repo, "PARTIAL (2026-07-29). Measured ...")
        _write(fake_repo, "alerts/README.md", self.STALE_LINE)
        vst.check_calibration_status_drift()
        assert len(vst.FAILURES) == 1
        assert "alerts/README.md" in vst.FAILURES[0]
        assert "PARTIAL" in vst.FAILURES[0]

    def test_source_moved_on_and_sibling_updated_passes(self, fake_repo):
        self._write_cfg(fake_repo, "PARTIAL (2026-07-29). Measured ...")
        _write(fake_repo, "alerts/README.md", self.CURRENT_LINE)
        vst.check_calibration_status_drift()
        assert vst.FAILURES == []

    def test_case_insensitive_match(self, fake_repo):
        """The YAML annotations use `OUTSTANDING`; the prose docs use
        `outstanding`. Both must be caught once the source has moved on."""
        self._write_cfg(fake_repo, "PARTIAL (2026-07-29). Measured ...")
        _write(fake_repo, "docs/operator-runbook.md",
               "Empirical confirmation is **outstanding** -- validate before rollout.\n")
        vst.check_calibration_status_drift()
        assert len(vst.FAILURES) == 1
        assert "docs/operator-runbook.md" in vst.FAILURES[0]

    def test_checks_every_shipped_file_independently(self, fake_repo):
        """All six shipped files in scope are checked, not just the first
        one that happens to exist."""
        self._write_cfg(fake_repo, "PARTIAL (2026-07-29). Measured ...")
        _write(fake_repo, "alerts/bsod-risk-prometheusrules.yaml", self.STALE_LINE)
        _write(fake_repo, "acm/bsod-risk-policy.yaml", self.STALE_LINE)
        vst.check_calibration_status_drift()
        flagged = {f.split(":")[0] for f in vst.FAILURES}
        assert flagged == {"alerts/bsod-risk-prometheusrules.yaml", "acm/bsod-risk-policy.yaml"}

    def test_missing_shipped_files_are_skipped_not_flagged(self, fake_repo):
        """A repo skeleton missing some of the shipped files (as every test
        fixture here is) must not be treated as a failure in itself -- only
        files that actually exist and actually contain the stale text."""
        self._write_cfg(fake_repo, "PARTIAL (2026-07-29). Measured ...")
        vst.check_calibration_status_drift()
        assert vst.FAILURES == []


class TestCheckStreamThresholdOrdering:
    """R-05 / U-30: a stream's FAIL floor may never sit below a documented
    upstream fix baseline, and WARN may never sit below FAIL.

    The real regression this guards: el10_1.fail shipped as 1.9.52 while
    multiqueue_fix_baseline is 1.9.53 (KCS-7136486), so virtio-win 1.9.52
    graded FAIL on OCP 4.19-4.21 but only WARN on OCP 4.22 -- severity
    softening triggered by a platform upgrade.
    """

    @staticmethod
    def _write_cfg(root, streams, mq_baseline="1.9.53"):
        return _write(root, "shared/virtio-win-thresholds.json", json.dumps({
            "multiqueue_fix_baseline": mq_baseline,
            "streams": streams,
        }))

    def test_fail_below_multiqueue_baseline_is_flagged(self, fake_repo):
        self._write_cfg(fake_repo, {
            "el9_6": {"fail": "1.9.53", "warn": "1.9.57"},
            "el10_1": {"fail": "1.9.52", "warn": "1.9.57"},   # the real bug
        })
        vst.check_stream_threshold_ordering()
        assert len(vst.FAILURES) == 1
        assert "el10_1" in vst.FAILURES[0]
        assert "1.9.52" in vst.FAILURES[0]
        assert "multiqueue_fix_baseline" in vst.FAILURES[0]

    def test_aligned_streams_pass(self, fake_repo):
        self._write_cfg(fake_repo, {
            "el9_6": {"fail": "1.9.53", "warn": "1.9.57"},
            "el10_1": {"fail": "1.9.53", "warn": "1.9.57"},
        })
        vst.check_stream_threshold_ordering()
        assert vst.FAILURES == []

    def test_null_fail_streams_are_skipped(self, fake_repo):
        """Capped legacy streams (el8_6/el9_2/el9_4) carry fail=null by design --
        the fix is simply unavailable there, so there is no floor to violate."""
        self._write_cfg(fake_repo, {
            "el8_6": {"fail": None, "warn": None, "max": "1.9.24"},
            "el9_4": {"fail": None, "warn": "1.9.46", "max": "1.9.46"},
        })
        vst.check_stream_threshold_ordering()
        assert vst.FAILURES == []

    def test_warn_below_fail_is_flagged(self, fake_repo):
        """An unreachable WARN band is a config error in its own right."""
        self._write_cfg(fake_repo, {
            "el9_6": {"fail": "1.9.57", "warn": "1.9.53"},
        })
        vst.check_stream_threshold_ordering()
        assert len(vst.FAILURES) == 1
        assert "below fail" in vst.FAILURES[0]

    def test_rpm_release_suffix_is_ignored_when_comparing(self, fake_repo):
        """Every layer compares only the upstream triple, so the invariant must
        too -- 1.9.53-0.el10_1 satisfies a 1.9.53 baseline."""
        self._write_cfg(fake_repo, {
            "el10_1": {"fail": "1.9.53-0.el10_1", "warn": "1.9.57-2.el10_1"},
        })
        vst.check_stream_threshold_ordering()
        assert vst.FAILURES == []

    def test_missing_baseline_is_flagged_not_silently_skipped(self, fake_repo):
        """If multiqueue_fix_baseline disappears, the invariant becomes
        uncheckable -- that must fail loudly rather than pass vacuously."""
        _write(fake_repo, "shared/virtio-win-thresholds.json",
               json.dumps({"streams": {"el9_6": {"fail": "1.9.53"}}}))
        vst.check_stream_threshold_ordering()
        assert len(vst.FAILURES) == 1
        assert "multiqueue_fix_baseline" in vst.FAILURES[0]

    def test_real_repo_config_satisfies_the_invariant(self):
        """Guards the shipped shared/virtio-win-thresholds.json itself."""
        vst.FAILURES.clear()
        try:
            vst.check_stream_threshold_ordering()
            assert vst.FAILURES == [], vst.FAILURES
        finally:
            vst.FAILURES.clear()


class TestCheckAgentsMdcEl10FailFloor:
    """L1: agents.mdc's el10_1 FAIL floor must match streams.el10_1.fail.

    The file is GitLab-only. The public export prove step runs this
    validator on a tree without .cursor/ -- missing must skip, not fail.
    """

    def _write_cfg(self, root, fail="1.9.53"):
        _write(root, "shared/virtio-win-thresholds.json",
               json.dumps({"streams": {"el10_1": {"fail": fail}}}))

    def test_matching_floor_passes(self, fake_repo):
        self._write_cfg(fake_repo, "1.9.53")
        _write(fake_repo, ".cursor/rules/agents.mdc",
               "el10_1: FAIL < 1.9.53\n")
        vst.check_agents_mdc_el10_fail_floor()
        assert vst.FAILURES == []

    def test_drifted_floor_fails(self, fake_repo):
        self._write_cfg(fake_repo, "1.9.53")
        _write(fake_repo, ".cursor/rules/agents.mdc",
               "el10_1: FAIL < 1.9.52\n")
        vst.check_agents_mdc_el10_fail_floor()
        assert len(vst.FAILURES) == 1
        assert "1.9.52" in vst.FAILURES[0]
        assert "1.9.53" in vst.FAILURES[0]

    def test_missing_agents_mdc_is_skipped_not_flagged(self, fake_repo):
        """publish-public-mirror proves this validator on the filtered
        public tree, which does not ship .cursor/rules/agents.mdc."""
        self._write_cfg(fake_repo, "1.9.53")
        vst.check_agents_mdc_el10_fail_floor()
        assert vst.FAILURES == []


class TestMainIntegration:
    def test_main_returns_zero_when_all_checks_pass(self, fake_repo, monkeypatch):
        """End-to-end sanity check: a fully-consistent synthetic repo produces
        exit code 0 with no FAILURES, proving main() wires all its checks
        together without a stray early-return swallowing a later one."""
        _write(fake_repo, "shared/io-timeout-thresholds.json",
               json.dumps({"risk_factor_at_or_below_seconds": 60}))
        _write(fake_repo, "alerts/bsod-risk-recording-rules.yaml",
               "expr: min by (vm_name) (bsod_io_timeout_value) <= bool 60\n"
               "# kubevirt_vmi_storage_read_times_seconds_total\n"
               "# kubevirt_vmi_storage_iops_read_total\n"
               "# kubevirt_vmi_storage_write_times_seconds_total\n"
               "# kubevirt_vmi_storage_iops_write_total\n")
        TestCheckStorageLatencyAlerts()._write_all(
            fake_repo, warn=0.5, crit=1.0, burst=5, trend=1.5, guest_crit=1.0)
        # check_storage_latency_alerts and check_host_cpu_contention_alert both
        # read alerts/bsod-risk-prometheusrules.yaml -- append rather than
        # overwrite, or one check's fixture clobbers the other's.
        _write(fake_repo, "shared/host-contention-thresholds.json",
               json.dumps({"throttle_ratio_warn": 0.25,
                           "runqueue_wait_per_cpu_warn": 1.0}))
        rules_path = fake_repo / "alerts" / "bsod-risk-prometheusrules.yaml"
        rules_path.write_text(
            rules_path.read_text()
            + TestCheckHostCPUContentionAlert.RULES_TEMPLATE.format(
                throttle=0.25, runq=1.0))
        # check_evidence_completeness_alert also reads
        # alerts/bsod-risk-prometheusrules.yaml -- append, don't overwrite.
        _write(fake_repo, "shared/evidence-completeness-thresholds.json",
               json.dumps({"fleet_warn_below_pct": 80}))
        rules_path.write_text(
            rules_path.read_text() + TestCheckEvidenceCompletenessAlert.RULES_TEMPLATE.format(ratio=0.8))
        TestCheckRiskScoringX100Parity()._write_cfg(fake_repo, {"crash": 3.0}, {"crash": 300})
        # check_risk_scoring_x100_parity and check_gate_domains_complete both
        # read shared/risk-scoring.json -- merge both fixtures' keys into one
        # file so neither check clobbers the other's config on disk.
        risk_scoring_path = fake_repo / "shared" / "risk-scoring.json"
        cfg = json.loads(risk_scoring_path.read_text())
        cfg["gate_domains"] = {"1": "crash"}
        cfg["domain_weights"] = {"crash": 3.0}
        risk_scoring_path.write_text(json.dumps(cfg))
        _write(fake_repo, "scripts/cnv-win-bsod-audit.sh", '  set_gate 1 "" ""\n')
        # F-05: check_gate11_fallback_matches_recording_rule reads both the
        # recording rules and Gate 11's fallback helper, so the synthetic repo
        # needs a fallback that references all four direction counters and the
        # label_replace union idiom.
        _write(fake_repo, "scripts/lib/prom-query.sh",
               "kubevirt_vmi_storage_read_times_seconds_total\n"
               "kubevirt_vmi_storage_iops_read_total\n"
               "kubevirt_vmi_storage_write_times_seconds_total\n"
               "kubevirt_vmi_storage_iops_write_total\n"
               "label_replace\n")
        TestCheckFailUpwardDefaultsMatch()._write_scripts(
            fake_repo, "crash", "crash", "KCS-VALIDATED", "KCS-VALIDATED")
        # el10_1 is required by check_agents_mdc_el10_1_floor as well as by
        # check_stream_threshold_ordering, and that checker also needs the
        # cursor rule it binds against. Omitting either made this test -- whose
        # entire job is proving main() wires EVERY check together -- fail for a
        # missing fixture rather than a real inconsistency.
        TestCheckStreamThresholdOrdering()._write_cfg(fake_repo, {
            "el9_6": {"fail": "1.9.53", "warn": "1.9.57"},
            "el10_1": {"fail": "1.9.53", "warn": "1.9.57"},
        })
        _write(fake_repo, ".cursor/rules/agents.mdc",
               "el10_1: FAIL < 1.9.53\n")

        exit_code = vst.main()
        assert exit_code == 0
        assert vst.FAILURES == []
