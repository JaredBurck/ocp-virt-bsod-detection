#!/usr/bin/env python3
"""Validate that referenced windows_exporter built-in metric names are real.

Guards against the exact failure mode found in v0.7.0 peer review: an alert
expression (and its ACM mirror, and its promtool test fixture) referenced
`windows_pagefile_usage_bytes`, a metric that windows_exporter's pagefile
collector does not emit -- the alert only "passed" promtool because the test
fixture fabricated that series name. `promtool` cannot catch this class of
bug because it has no knowledge of what a real exporter emits; it only
checks that PromQL is syntactically valid and matches the given input series.

This script maintains a small, explicit allowlist of real metric names for
the windows_exporter collectors this framework actually uses (logical_disk,
pagefile, service) and scans all alert/ACM/dashboard/doc sources for any
`windows_<collector>_*` token, failing if one isn't on the allowlist.

When adding a new windows_exporter metric to this framework, add it to
ALLOWED_WINDOWS_EXPORTER_METRICS below with a comment citing the upstream
collector doc (https://github.com/prometheus-community/windows_exporter/blob/
master/docs/collector.<name>.md) that confirms it's real.

Usage:
    python3 scripts/ci/validate-metric-names.py
"""
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

# Real windows_exporter metrics for the collectors this framework relies on.
# Source: https://github.com/prometheus-community/windows_exporter/tree/master/docs
ALLOWED_WINDOWS_EXPORTER_METRICS = {
    # docs/collector.logical_disk.md
    "windows_logical_disk_read_seconds_total",
    "windows_logical_disk_reads_total",
    "windows_logical_disk_write_seconds_total",
    "windows_logical_disk_writes_total",
    "windows_logical_disk_free_bytes",
    "windows_logical_disk_size_bytes",
    "windows_logical_disk_idle_seconds_total",
    "windows_logical_disk_read_bytes_total",
    "windows_logical_disk_write_bytes_total",
    # docs/collector.pagefile.md -- NOTE: there is no windows_pagefile_usage_bytes.
    # Utilization must be derived as (limit-free)/limit.
    "windows_pagefile_free_bytes",
    "windows_pagefile_limit_bytes",
    # docs/collector.service.md
    "windows_service_state",
    "windows_service_status",
    "windows_service_start_mode",
    "windows_service_info",
    # docs/collector.cpu.md (R-46, Wave 7 N/A -- Recommendation 6): the cpu
    # collector is enabled by default and by
    # windows-exporter/install-windows-exporter.ps1's ENABLED_COLLECTORS list,
    # but nothing downstream consumed it before this. windows_cpu_time_total
    # carries `core`+`mode` labels (mode in dpc/idle/interrupt/privileged/user);
    # utilization is derived as 100 - (idle mode's share), matching upstream's
    # own documented usage example.
    "windows_cpu_time_total",
    # docs/collector.memory.md (R-46): also enabled by default and by the
    # installer. windows_memory_physical_free_bytes/_total_bytes are gauges
    # with no labels; utilization = 100 - 100*free/total, matching upstream's
    # documented usage example (same shape as the existing pagefile derivation
    # below).
    "windows_memory_physical_free_bytes",
    "windows_memory_physical_total_bytes",
}

# Files known to reference windows_exporter metric names.
SCAN_FILES = [
    "alerts/bsod-risk-guest-alerts.yaml",
    "alerts/tests.yaml",
    "acm/bsod-risk-policy.yaml",
    "dashboards/bsod-risk-overview.json",
    "windows-exporter/README.md",
    "windows-exporter/bsod-textfile-collector.ps1",
    "docs/design/roadmap-v1.0.md",
    "docs/operator-runbook.md",
]

METRIC_TOKEN_RE = re.compile(r"\bwindows_[a-z][a-z0-9_]*\b")

# --- Platform metrics (F-01/F-02 follow-up, v0.26.0) -------------------------
#
# Until v0.26.0 this validator covered `windows_*` tokens ONLY, and the two
# hypervisor-side alert CRs were not even in SCAN_FILES. A typo'd or renamed
# `kubevirt_*` / `container_*` / `node_*` metric therefore shipped silently:
# the expression simply matched nothing, the alert never fired, and no test
# objected -- promtool validates PromQL syntax, not whether a metric exists.
#
# That is the same failure shape as peer-review F-02 (an alert built on
# counters a default cluster never populates) and F-01 (a whole direction of
# storage telemetry nobody had referenced). Both were found by hand. This
# closes the typo/rename half of the class structurally.
#
# Every entry here is a metric this framework actually consumes, with the
# component that emits it. Add one only when the metric has been confirmed to
# exist on a real cluster -- an allowlist populated by guessing would restore
# exactly the false confidence it exists to remove. Note that presence in this
# list asserts the NAME is real, not that the series is populated in a given
# cluster's configuration; that second question is shared/alert-liveness.json's.
ALLOWED_PLATFORM_METRICS = {
    # --- KubeVirt (virt-handler /metrics, per-VMI) ---
    "kubevirt_vmi_storage_read_times_seconds_total",
    "kubevirt_vmi_storage_write_times_seconds_total",
    "kubevirt_vmi_storage_iops_read_total",
    "kubevirt_vmi_storage_iops_write_total",
    "kubevirt_vmi_memory_used_bytes",
    "kubevirt_vmi_memory_domain_bytes",
    "kubevirt_vmi_info",
    "kubevirt_vmi_migration_phase_transition_time_from_creation_seconds_count",
    "kubevirt_vm_running_status_last_transition_timestamp_seconds",
    # Upstream in kubevirt/kubevirt#17836 but NOT in any released HCO/CNV build
    # -- confirmed absent on live OCP Virt 4.19.25 and CNV 4.21.13. Allowed
    # here because the NAME is correct; its unavailability is recorded as
    # known-inert in shared/alert-liveness.json, which is the right place for
    # that distinction.
    "kubevirt_vmi_guest_os_panic_total",
    # --- cAdvisor (kubelet job, default OCP monitoring stack) ---
    "container_cpu_cfs_periods_total",
    "container_cpu_cfs_throttled_periods_total",
    # --- node_exporter (default OCP monitoring stack) ---
    # /proc/schedstat run-queue wait. Confirmed present on OCP 4.18.26 (72
    # series across 6 nodes).
    "node_schedstat_waiting_seconds_total",
    # PSI. Kept allowlisted because the NAME is correct upstream, but it is
    # NOT used by any shipped rule: it returned zero series on OCP 4.18.26 /
    # ARO even with node_exporter healthy. Do not build an alert on it without
    # first confirming the series exists on the target platform.
    "node_pressure_cpu_waiting_seconds_total",
    # --- kube-state-metrics ---
    "kube_node_labels",
}

PLATFORM_TOKEN_RE = re.compile(
    r"\b(?:kubevirt_|container_|node_pressure_|node_schedstat_|kube_node_)[a-z][a-z0-9_]*\b")

# Files that reference platform metric names. Deliberately includes the two
# hypervisor alert CRs and the recording rules, which the windows_* scan never
# covered.
PLATFORM_SCAN_FILES = [
    "alerts/bsod-risk-prometheusrules.yaml",
    "alerts/bsod-risk-recording-rules.yaml",
]


def check_evidence_completeness_metric_name() -> int:
    """Issue K: the exporter script and its recording rule must agree on
    metric names.

    scripts/cnv-bsod-fleet-exporter.sh is the single source of truth for the
    metric names it emits -- exactly the class of drift this file already
    guards against for windows_exporter's *upstream* metric names, just
    applied to metrics this framework defines itself instead of ones it
    consumes. A rename on one side without the other would leave the
    recording rule silently querying a metric nothing emits (empty result,
    no error) or the exporter emitting a metric nothing reads.

    Checks every metric the recording rule's sum()/sum() ratio actually
    depends on (bsod_vm_checks_assessed, bsod_vm_checks_total) -- not just
    the single legacy name this check originally covered
    (bsod_evidence_completeness_percent, which the recording rule no longer
    reads at all since the aggregation moved to raw counts; that name is
    checked separately below purely for "does the exporter still emit its
    own documented TYPE line", since nothing downstream is required to
    consume it -- it is a per-VM convenience/dashboard gauge only).
    """
    exporter = REPO_ROOT / "scripts" / "cnv-bsod-fleet-exporter.sh"
    recording_rules = REPO_ROOT / "alerts" / "bsod-risk-recording-rules.yaml"
    if not exporter.is_file() or not recording_rules.is_file():
        return 0

    exporter_text = exporter.read_text()
    rc = 0

    # The convenience gauge: must still exist in the exporter, but has no
    # required downstream consumer.
    if not re.search(r'echo "# TYPE (bsod_evidence_completeness_percent) gauge"',
                      exporter_text):
        print("FAIL: scripts/cnv-bsod-fleet-exporter.sh: could not find the "
              "bsod_evidence_completeness_percent TYPE line -- update this "
              "checker if the metric was intentionally renamed or removed")
        rc = 1

    # The two raw counters the recording rule's sum()/sum() ratio actually
    # depends on -- both must round-trip exporter -> recording rule.
    rules_text = recording_rules.read_text()
    for metric_name in ("bsod_vm_checks_assessed", "bsod_vm_checks_total"):
        pattern = r'echo "# TYPE (' + re.escape(metric_name) + r') gauge"'
        m = re.search(pattern, exporter_text)
        if not m:
            print(f"FAIL: scripts/cnv-bsod-fleet-exporter.sh: could not find "
                  f"the {metric_name} TYPE line -- update this checker if "
                  f"the metric was intentionally renamed")
            rc = 1
            continue
        if metric_name not in rules_text:
            print(f"FAIL: alerts/bsod-risk-recording-rules.yaml does not "
                  f"reference '{metric_name}' -- "
                  f"scripts/cnv-bsod-fleet-exporter.sh emits this metric "
                  f"name but bsod:fleet_evidence_completeness:ratio appears "
                  f"to query a different one (rename drift)")
            rc = 1
    return rc


def main() -> int:
    rc = 0
    seen_unknown = set()
    rc |= check_evidence_completeness_metric_name()
    # Only EXECUTABLE references are checked, so the CRs are parsed and just
    # their `expr:` values scanned. A line-based scan over these files produces
    # false positives from the explanatory prose this repo puts in comments and
    # in `prerequisite:` / `calibration_status:` annotations -- which
    # legitimately name metrics, including ones deliberately NOT used (e.g. the
    # verification command `grep node_pressure_cpu`). Flagging documentation
    # would train reviewers to ignore this check, which is worse than not
    # having it.
    for rel_path in PLATFORM_SCAN_FILES:
        path = REPO_ROOT / rel_path
        if not path.exists():
            continue
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            print(f"FAIL: {rel_path}: could not parse as YAML ({exc})")
            rc = 1
            continue
        for group in (doc or {}).get("spec", {}).get("groups", []):
            for rule in group.get("rules", []):
                name = rule.get("alert") or rule.get("record") or "<unnamed>"
                for token in PLATFORM_TOKEN_RE.findall(rule.get("expr", "")):
                    if token in ALLOWED_PLATFORM_METRICS:
                        continue
                    key = (rel_path, name, token)
                    if key in seen_unknown:
                        continue
                    seen_unknown.add(key)
                    print(
                        f"FAIL: {rel_path}: {name} uses unknown platform "
                        f"metric '{token}' -- not in ALLOWED_PLATFORM_METRICS. "
                        f"A typo or upstream rename here matches nothing, so "
                        f"the rule silently never fires; confirm the name "
                        f"against a live cluster before adding it."
                    )
                    rc = 1

    for rel_path in SCAN_FILES:
        path = REPO_ROOT / rel_path
        if not path.exists():
            continue
        text = path.read_text(errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in METRIC_TOKEN_RE.finditer(line):
                token = match.group(0)
                if token in ALLOWED_WINDOWS_EXPORTER_METRICS:
                    continue
                # Skip generic prose mentions like "windows_exporter" itself
                # and label/annotation identifiers, not metric names.
                if token in ("windows_exporter",):
                    continue
                key = (rel_path, token)
                if key in seen_unknown:
                    continue
                seen_unknown.add(key)
                print(
                    f"FAIL: {rel_path}:{lineno}: unknown windows_exporter metric "
                    f"'{token}' -- not in ALLOWED_WINDOWS_EXPORTER_METRICS "
                    f"(verify against upstream docs/collector.*.md before adding)"
                )
                rc = 1

    if rc == 0:
        print(f"OK: all platform metric references match the verified allowlist "
              f"({len(ALLOWED_PLATFORM_METRICS)} known KubeVirt/cAdvisor/node metrics)")
        print(f"OK: all windows_exporter metric references match the verified allowlist "
              f"({len(ALLOWED_WINDOWS_EXPORTER_METRICS)} known metrics)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
