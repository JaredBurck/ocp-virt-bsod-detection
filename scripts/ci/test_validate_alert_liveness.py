"""Regression tests for scripts/ci/validate-alert-liveness.py.

Peer-review finding F-02 (v0.25.0): BSODRisk_HostCPUContention passed its own
promtool firing test while being provably silent at 100% node contention on a
default cluster, because its cAdvisor CFS counters only exist when a CPU limit
is set. It was the THIRD alert of that class to ship (after BSODRisk_GuestCrash
and the VirtIO GPU dump check), and no test could catch any of them: a promtool
test author supplies the input series, so a firing test proves the expression
arithmetic, never that the samples occur in reality.

These tests pin the two halves of the guard that replace that missing check --
the metric extractor (which must see through recording rules and must NOT
mistake label names for metrics) and the declaration comparison (which must
fail on an undeclared alert, a stale entry, and a drifted expression). If
either half silently stops working, the framework goes back to shipping
alerts whose liveness nobody has been forced to state.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-alert-liveness.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_alert_liveness", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


val = _load_module()


class TestExtractMetrics:
    """The extractor decides what the declaration is compared against.

    Over-extraction (counting a label as a metric) makes every declaration
    fail noisily; under-extraction makes a new dependency slip through
    silently, which is the failure mode that matters.
    """

    def test_plain_metric(self):
        assert val.extract_metrics("foo_total > 0", {}) == {"foo_total"}

    def test_label_selector_contents_are_not_metrics(self):
        expr = 'kubevirt_vmi_info{os=~"windows|win.*",evictable="false"} == 1'
        assert val.extract_metrics(expr, {}) == {"kubevirt_vmi_info"}

    def test_by_clause_labels_are_not_metrics(self):
        expr = "sum by (name, namespace, drive) (rate(disk_reads_total[1h]))"
        assert val.extract_metrics(expr, {}) == {"disk_reads_total"}

    def test_on_clause_labels_are_not_metrics(self):
        expr = "a_total and on(name, namespace) b_total"
        assert val.extract_metrics(expr, {}) == {"a_total", "b_total"}

    def test_label_replace_string_args_are_not_metrics(self):
        """BSODRisk_GuestUnexpectedRestart's real shape.

        `label_replace(up{...} == 0, "name", "$1", "vm_name", "(.*)")` would
        otherwise declare `name` and `vm_name` as required metric series.
        """
        expr = 'label_replace(up{job=~"x.*"} == 0, "name", "$1", "vm_name", "(.*)")'
        assert val.extract_metrics(expr, {}) == {"up"}

    def test_durations_and_functions_are_not_metrics(self):
        expr = "max_over_time(rate(foo_total[5m])[1h:5m]) >= 5"
        assert val.extract_metrics(expr, {}) == {"foo_total"}

    def test_resolves_through_recording_rule(self):
        """A recording rule is only as live as its own inputs.

        The declaration must be about the KubeVirt counters underneath, not
        the derived series, because that is the level at which "does this
        exist on a real cluster?" is answerable.
        """
        recordings = {
            "bsod:vmi_disk_latency:avg_1h":
                "sum by (name) (rate(kubevirt_vmi_storage_read_times_seconds_total[1h]))"
                " / sum by (name) (rate(kubevirt_vmi_storage_iops_read_total[1h]))",
        }
        assert val.extract_metrics(
            "bsod:vmi_disk_latency:avg_1h >= 0.5", recordings) == {
                "kubevirt_vmi_storage_read_times_seconds_total",
                "kubevirt_vmi_storage_iops_read_total",
        }

    def test_nested_recording_rules_resolve(self):
        recordings = {
            "bsod:outer:gauge": "sum(bsod:inner:gauge)",
            "bsod:inner:gauge": "max by (vm_name) (raw_metric_total)",
        }
        assert val.extract_metrics("bsod:outer:gauge > 1", recordings) == {
            "raw_metric_total"}

    def test_recursion_is_bounded(self):
        """A self-referential recording rule must not hang CI."""
        recordings = {"bsod:loop:gauge": "bsod:loop:gauge + other_total"}
        assert "other_total" in val.extract_metrics(
            "bsod:loop:gauge > 0", recordings)


class TestStatusVocabulary:
    def test_requires_nondefault_config_is_a_valid_status(self):
        """The F-02 category must exist as a distinct, nameable state.

        Collapsing it into requires-optional-component would lose the
        distinction that matters: an operator can choose to install an
        optional component, but cannot know that KubeVirt's default
        (requests, no limits) silently disables an alert.
        """
        assert "requires-nondefault-config" in val.VALID_STATUS

    def test_statuses_needing_a_precondition_exclude_default_cluster(self):
        assert "default-cluster" not in val.STATUS_REQUIRING_PRECONDITION
        assert val.STATUS_REQUIRING_PRECONDITION <= set(val.VALID_STATUS)


class TestShippedRegistry:
    """Assertions against the real, shipped declarations."""

    @pytest.fixture(scope="class")
    def registry(self):
        return json.loads(val.REGISTRY_FILE.read_text())["alerts"]

    def test_every_shipped_alert_is_declared(self, registry):
        assert set(val.load_alerts()) == set(registry)

    def test_validator_passes_on_the_real_repo(self):
        assert val.main() == 0

    def test_cfs_throttle_alert_is_declared_nondefault(self, registry):
        """Pins F-02's resolution.

        The CFS expression cannot produce series without a CPU limit, and
        KubeVirt sets none by default. It kept that limitation after v0.26.0 --
        what changed is that it is now NAMED for what it measures, so the
        limitation is honest rather than misleading. If someone relabels this
        default-cluster without changing the expression, this test objects.
        """
        entry = registry["BSODRisk_VirtLauncherCPUThrottled"]
        assert entry["status"] == "requires-nondefault-config"
        assert "limit" in entry["precondition"].lower()

    def test_host_cpu_contention_no_longer_depends_on_cfs_counters(self, registry):
        """The whole point of F-02: this name must carry a signal that works.

        The CFS counters are populated only when a CPU limit exists, so an
        alert claiming to detect node contention must not be built on them.
        This fails if anyone points the name back at the limit-dependent
        metric.
        """
        entry = registry["BSODRisk_HostCPUContention"]
        assert not any("cfs" in s.lower() for s in entry["required_series"]), (
            "BSODRisk_HostCPUContention must not depend on CFS throttle "
            "counters -- that is the F-02 defect")
        assert entry["required_series"] == [
            "kube_node_labels", "node_schedstat_waiting_seconds_total"]

    def test_contention_signal_was_verified_on_a_live_cluster(self, registry):
        """The declaration is now backed by evidence, not belief.

        This entry originally read requires-optional-component with the
        precondition "believed present on RHCOS but NOT confirmed", because
        the alert used Linux PSI. Checking that on a live OCP 4.18.26 cluster
        found PSI ABSENT -- zero node_pressure_* series with node_exporter
        healthy -- so the alert was rebased onto /proc/schedstat run-queue
        wait, which IS present. Recording the doubt rather than assuming the
        series existed is the only reason it was checked before release.

        default-cluster is therefore a verified claim here, not a hedge.
        """
        entry = registry["BSODRisk_HostCPUContention"]
        assert entry["status"] == "default-cluster"
        assert entry["required_series"] == [
            "kube_node_labels", "node_schedstat_waiting_seconds_total"]

    def test_psi_is_not_used_by_any_shipped_rule(self, registry):
        """PSI proved unavailable on the target platform.

        It stays in the metric-name allowlist because the NAME is correct
        upstream, but no alert may depend on it without a fresh availability
        check -- reintroducing it blindly would recreate F-02 a fourth time.
        """
        for name, entry in registry.items():
            assert not any(s.startswith("node_pressure_")
                           for s in entry["required_series"]), (
                f"{name} depends on PSI, which returned zero series on the "
                f"live validation cluster (OCP 4.18.26 / ARO)")

    def test_guest_crash_is_declared_inert(self, registry):
        """CLAUDE.md documents this alert as unfirable on any shipping release."""
        assert registry["BSODRisk_GuestCrash"]["status"] == "known-inert"

    def test_every_caveated_entry_states_its_precondition(self, registry):
        for name, entry in registry.items():
            if entry["status"] in val.STATUS_REQUIRING_PRECONDITION:
                assert entry["precondition"].strip(), (
                    f"{name}: status {entry['status']!r} without a "
                    f"precondition tells an operator nothing actionable")

    def test_no_entry_claims_more_than_the_expression_uses(self, registry):
        """Guards the opposite drift from a missing dependency.

        A declaration listing metrics the alert no longer reads is a claim
        about liveness that is no longer being checked against anything.
        """
        recordings = val.load_recording_rules()
        for name, expr in val.load_alerts().items():
            assert set(registry[name]["required_series"]) == \
                val.extract_metrics(expr, recordings), name
