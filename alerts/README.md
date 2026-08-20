# PrometheusRule Alerts Deployment Guide for BSOD Detection

## Overview

This guide covers deploying the Prometheus alerting and recording rules that detect BSOD (Blue Screen of Death) risk conditions on Windows VMs running on OpenShift Virtualization. Deploy the rules as `PrometheusRule` Custom Resources (CRs) in the `openshift-cnv` namespace.

Three PrometheusRule CRs work together:

1. **Hypervisor alerts** -- 13 alerting rules based on KubeVirt metrics (hypervisor-side)
2. **Recording rules** -- 11 recording rules (storage latency averages for read, write and worst-direction, per-VM risk factor count, CPU model/vendor group count, cluster risk summary, driver compliance ratio, fleet evidence completeness ratio)
3. **Guest alerts** -- 9 alerting rules based on `windows_exporter` metrics (guest-side)

Arch-capabilities (KCS-7125237) is not a Prometheus alert; use Gate 9.

## Components

| File | Kind | Name | Purpose |
|------|------|------|---------|
| `bsod-risk-prometheusrules.yaml` | PrometheusRule | `bsod-risk-alerts` | 13 hypervisor-side alerting rules |
| `bsod-risk-recording-rules.yaml` | PrometheusRule | `bsod-risk-recording-rules` | 11 recording rules (storage latency averages for read, write and worst-direction, per-VM risk factor count, CPU model count, cluster risk summary, driver compliance, fleet evidence completeness ratio) |
| `bsod-risk-guest-alerts.yaml` | PrometheusRule | `bsod-risk-guest-alerts` | 9 guest-side alerting rules (requires `windows_exporter`) |
| `tests.yaml` | promtool test | -- | 78 test cases across `alert_rule_test` (60) and `promql_expr_test` (18) blocks, positive + negative, for all rules |

## Prerequisites

Before deploying, confirm:

- OpenShift Container Platform (OCP) 4.12+ with OpenShift Virtualization (CNV) installed
- `oc` CLI with permissions to create `PrometheusRule` in `openshift-cnv`
- `promtool` installed locally (for running tests -- optional)
- For guest alerts: `windows_exporter` deployed in Windows VMs (see `windows-exporter/README.md`)
- For AMD microcode alert on OCP < 4.14: kube-state-metrics label allowlist configured (see below)
- For `BSODRisk_MemoryPressure`/`BSODRisk_EvictionBlocked`: Windows VMs carry a `vm.kubevirt.io/os` annotation matching `windows|win.*` (see "`os` Label Dependency" below)

## Alert Reference

### Hypervisor Alerts (`bsod-risk-prometheusrules.yaml`)

| Alert | Severity | For | Domain | KCS | BSOD Stop Codes | Confidence |
|-------|----------|-----|--------|-----|-----------------|------------|
| `BSODRisk_StorageLatencyElevated` | warning | 15m | storage | 7132512 | MEMORY_MANAGEMENT (0x1A), KERNEL_DATA_INPAGE_ERROR (0x7A), PAGE_FAULT_IN_NONPAGED_AREA (0x50), CRITICAL_PROCESS_DIED (0xEF) | [KCS-VALIDATED] -- thresholds calibration PARTIAL, see below |
| `BSODRisk_StorageLatencyHigh` | critical | 10m | storage | 7132512 | MEMORY_MANAGEMENT (0x1A), KERNEL_DATA_INPAGE_ERROR (0x7A), PAGE_FAULT_IN_NONPAGED_AREA (0x50), CRITICAL_PROCESS_DIED (0xEF) | [KCS-VALIDATED] -- thresholds calibration PARTIAL, see below |
| `BSODRisk_StorageLatencyBurst` | critical | 0m | storage | 7132512 | MEMORY_MANAGEMENT (0x1A), KERNEL_DATA_INPAGE_ERROR (0x7A), PAGE_FAULT_IN_NONPAGED_AREA (0x50), CRITICAL_PROCESS_DIED (0xEF) | [KCS-VALIDATED] -- tail-latency approximation, thresholds calibration PARTIAL |
| `BSODRisk_StorageLatencyTrending` | warning | 30m | storage | 7132512 | MEMORY_MANAGEMENT (0x1A), KERNEL_DATA_INPAGE_ERROR (0x7A), PAGE_FAULT_IN_NONPAGED_AREA (0x50), CRITICAL_PROCESS_DIED (0xEF) | [KCS-VALIDATED] |
| `BSODRisk_MemoryPressure` | warning | 30m | resource | 7132512 | MEMORY_MANAGEMENT (0x1A) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_GuestCrash` | critical | 0m | crash | 7141291 | varies | [UNVALIDATED] -- metric not yet shipped, `bsod_status: preview` label (see note below) |
| `BSODRisk_HeterogeneousCPUMigration` | warning | 0m | cpu | 7125237 | CLOCK_WATCHDOG_TIMEOUT (0x101), KERNEL_MODE_EXCEPTION_NOT_HANDLED (0x9C) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_AMDNodeRequiresMicrocodeVerification` | info | 30m | cpu | 7132511 | PFN_LIST_CORRUPT (0x4E) | [KCS-VALIDATED] |
| `BSODRisk_EvictionBlocked` | warning | 5m | config | 7132512 | N/A (dirty shutdown) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_HostCPUContention` | warning | 10m | cpu | 7132511 | CLOCK_WATCHDOG_TIMEOUT (0x101), MACHINE_CHECK_EXCEPTION (0x9C) | [GENERAL-KNOWLEDGE] -- run-queue based since v0.26.0 (F-02); threshold PARTIALLY calibrated, see below |
| `BSODRisk_VirtLauncherCPUThrottled` | warning | 10m | cpu | 7132511 | CLOCK_WATCHDOG_TIMEOUT (0x101), MACHINE_CHECK_EXCEPTION (0x9C) | [GENERAL-KNOWLEDGE] -- the pre-v0.26.0 CFS rule, renamed to what it measures (F-02); requires CPU limits to produce series |
| `BSODRisk_FleetEvidenceIncomplete` | warning | 30m | coverage | N/A | N/A (observability signal, not a BSOD-trigger claim) | [UNVALIDATED] -- threshold UNCALIBRATED, see below |
| `BSODRisk_ExporterCollectionFailing` | warning | 15m | coverage | N/A | N/A (dead-man's-switch for the exporter itself) | [UNVALIDATED] |

> **Storage latency calibration status:** `BSODRisk_StorageLatencyElevated`/`High`/`Burst` (and `BSODRisk_StorageLatencyTrending`) use thresholds from `shared/storage-latency-thresholds.json` (0.5s sustained warning / 1.0s sustained critical / 5s burst), adopted 2026-07-28 to replace a defective 30s/op mean that could only fire after a Windows guest had already bugchecked (H-5). **Calibration is PARTIAL**: measured 2026-07-29 against 15 concurrently running Windows VMs on external ODF/Ceph RBD over a 24h window (p99 0.14s / max 0.17s during a simultaneous 15-VM boot storm, 3.0x under the 0.5s WARN threshold) -- see `_calibration_status` in `shared/storage-latency-thresholds.json` for the full measurement and, importantly, what it does *not* establish (production-scale p95, brownout detection, margin at fleet scale). Before fleet rollout, run `scripts/cnv-storage-latency-calibrate.sh` and the procedure in `docs/admin-runbook.md`'s "Storage latency calibration" section against a cluster with real production Windows I/O and confirm p95 still sits well below `sustained_warn_seconds`.

> **`BSODRisk_GuestCrash` status (2026-07-10):** The `kubevirt_vmi_guest_os_panic_total`
> metric this alert queries does **not exist on any shipping OpenShift Virtualization
> release** as of this writing -- confirmed absent via direct Prometheus/API query on a
> live OCP Virt 4.19.25 cluster.
>
> Upstream KubeVirt added the metric in
> [kubevirt/kubevirt#17836](https://github.com/kubevirt/kubevirt/pull/17836), and the
> first alert consuming it (`VMNonRecoverableOSPanic`) merged upstream on
> 2026-06-30 ([kubevirt/kubevirt#18004](https://github.com/kubevirt/kubevirt/pull/18004));
> neither has reached a released HCO/CNV build.
>
> `BSODRisk_GuestCrash` is shipped as a forward-looking placeholder -- it is harmless
> (it never fires) but **do not present it as a working detection mechanism
> today**. Until the metric ships, inspect virt-launcher logs for
> `GUEST_PANICKED` / `GUEST_CRASHLOADED` and attach them to the support case
> with `cnv-win-bsod-audit.sh --json`.

> **`BSODRisk_HostCPUContention` calibration status (R-45, N-07, added Wave 7):** This
> alert closes a real gap -- before it existed, no signal anywhere in this framework
> measured *actual, observed* host-side CPU contention (a repo-wide grep for
> steal/PSI/cpu_pressure/cfs_throttl/noisy neighbor returned zero hits outside one
> docstring in `bsod_resource_checks.py`, which only reads the K8s pod's *declared*
> resource request vs. node capacity). It reuses `container_cpu_cfs_throttled_periods_total`
> / `container_cpu_cfs_periods_total`, cAdvisor cgroup counters already scraped by OCP's
> default monitoring stack (kubelet job) -- no new collection agent, ServiceMonitor, or
> guest change is required. The 25% throttle-ratio threshold
> (`shared/host-contention-thresholds.json`) is **UNCALIBRATED** -- adopted as a starting
> point pending a live induced-contention validation run (constrain a virt-launcher pod's
> CPU limit below its actual demand and confirm the alert fires and clears). See
> `_calibration_status` in `shared/host-contention-thresholds.json` for what remains
> unestablished.

> **`BSODRisk_FleetEvidenceIncomplete` / `BSODRisk_ExporterCollectionFailing` (Issue K,
> coordinated with R-27, added v0.23.0):** Fleet-wide *observability* signals, not BSOD-risk
> signals -- they detect when the framework itself is failing to reach a verdict on a
> significant share of checks, not a BSOD trigger on any VM. Produced by the
> `bsod-fleet-exporter` Deployment (`exporter/`), which re-runs `cnv-win-bsod-audit.sh --json`
> on an interval and exposes per-VM `bsod_vm_checks_assessed`/`bsod_vm_checks_total` gauges.
> `BSODRisk_FleetEvidenceIncomplete` fires on `bsod:fleet_evidence_completeness:ratio` (a
> checks-weighted `sum()/sum()`, not an unweighted average of per-VM percentages -- see the
> recording rule's own comments for why) dropping below 80% for 30m; the 80% threshold in
> `shared/evidence-completeness-thresholds.json` is **UNCALIBRATED**, see that file's
> `_calibration_status`. `BSODRisk_ExporterCollectionFailing` is a dead-man's-switch on
> `bsod_evidence_exporter_last_collection_success` -- it catches the exporter pod being alive
> and scrapable but every collection attempt failing, which the standard `up{job=...}` Prometheus
> metric alone would miss. See `[exporter/README.md](../exporter/README.md)` for deployment,
> the ACM-inclusion decision, and the interval-vs-fleet-size guidance
> (`bsod_evidence_exporter_interval_below_recommended`).

### Recording Rules (`bsod-risk-recording-rules.yaml`)

| Record | Expression | Purpose |
|--------|-----------|---------|
| `bsod:vmi_disk_latency:avg_1h` | `sum by(name,namespace,drive)(rate(read_times[1h])) / sum by(...)(rate(iops_read[1h]))` | 1-hour average disk read latency per VM |
| `bsod:vmi_disk_latency:avg_24h` | Same formula with `[24h]` window | 24-hour baseline for trend detection |
| `bsod:vm_risk_factor_count:gauge` | Sums three guest-sourced risk booleans (outdated driver, low `IoTimeoutValue`, crash dump disabled) per VM | Pre-computed pre-crash risk context (0-3); consumed by `BSODRisk_GuestCrash`'s annotations and `bsod:cluster_risk_summary:gauge` |
| `bsod:cluster_cpu_model_count:gauge` | Counts distinct CPU capability groups (vendor + feature-signature) from `kube_node_labels` | Drives `BSODRisk_HeterogeneousCPUMigration` (> 1 = heterogeneous) |
| `bsod:cluster_risk_summary:gauge` | Aggregates `bsod:vm_risk_factor_count:gauge` across all VMs | Fleet-wide total active risk factors |
| `bsod:cluster_driver_compliance:ratio` | Ratio of VMs with current virtio-win driver to total VMs | Fleet driver compliance fraction (0.0–1.0) |
| `bsod:fleet_evidence_completeness:ratio` | `sum(bsod_vm_checks_assessed) / sum(bsod_vm_checks_total)` | Checks-weighted fleet-wide evidence completeness (0.0–1.0); drives `BSODRisk_FleetEvidenceIncomplete`. Requires the `bsod-fleet-exporter` Deployment (`exporter/`), not `windows_exporter` |

The storage latency recording rules use `sum by()` aggregation to handle label churn from virt-handler restarts and VM rescheduling. A denominator guard (`> 0`) prevents NaN/Inf series on idle disks.

**Dependency:** `BSODRisk_StorageLatencyElevated`, `BSODRisk_StorageLatencyHigh`, and `BSODRisk_StorageLatencyTrending` depend on the `bsod:vmi_disk_latency:avg_1h`/`avg_24h` recording rules and never fire without them. `BSODRisk_StorageLatencyBurst` is the one exception -- it evaluates raw `kubevirt_vmi_storage_*` counters directly (via `max_over_time`) so it can fire even if the recording rules are not deployed.

**Latency scale:** Prometheus hypervisor/guest latency alerts use a **seconds** scale near the ~60s VirtIO `IoTimeoutValue` (KCS-7132512). The Python analyzer and guest PowerShell collector use a separate **milliseconds** early-warning scale (WARN >= 50 ms / FAIL >= 500 ms). These thresholds are intentional and not interchangeable.

**Recording rule prerequisites:**

- `bsod:cluster_cpu_model_count:gauge` requires kube-state-metrics to expose KubeVirt CPU-vendor node labels (`cpu-vendor.node.kubevirt.io/*`). On OCP 4.14+, these are exposed by default (`nodes=[*]` allowlist). On older versions, configure the kube-state-metrics label allowlist manually (see "kube-state-metrics Label Allowlist" below). Without the labels, the rule produces no series and `BSODRisk_HeterogeneousCPUMigration` never fires.
- `bsod:vm_risk_factor_count:gauge`, `bsod:cluster_risk_summary:gauge`, and `bsod:cluster_driver_compliance:ratio` require `windows_exporter` with `bsod-textfile-collector.ps1` deployed inside Windows VMs. Without guest metrics, these rules produce no series.

**Renamed alert:** `BSODRisk_RecentVMMigrationDetected` (info severity, fired on any migration) has been replaced by `BSODRisk_HeterogeneousCPUMigration` (warning severity). The new alert fires only when a migration occurs AND the cluster has heterogeneous CPU vendors (AMD + Intel worker nodes). It does not fire on homogeneous clusters or when vendor labels are absent (pre-OCP 4.14 without allowlist).

**Cardinality guard (F13, v0.17.0):** `docs/info/e2e-validation-r9-r10.md`'s "Cardinality Check" section documents the real risk of an unbounded label silently landing in a `by()`/`count by()` clause here (< 500 series per cluster expected on a real fleet). `scripts/ci/validate-recording-rule-cardinality.py` enforces this in CI: every label in every `by()`/`count by()` clause above must be on that script's reviewed `ALLOWED_BY_LABELS` allowlist (`name`, `namespace`, `drive`, `vm_name`, and the five `label_cpu_feature_node_kubevirt_io_*` node-scoped feature labels, each bounded by VM count, disk count, or worker-node count respectively). Adding a new label to a `by()` clause requires a matching allowlist entry with a cardinality justification in the same change, or CI fails.

### Guest Alerts (`bsod-risk-guest-alerts.yaml`)

| Alert | Severity | For | Domain | KCS | Metric Source | Confidence |
|-------|----------|-----|--------|-----|---------------|------------|
| `BSODRisk_GuestDiskLatencyHigh` | critical | 10m | storage | 7132512 | `windows_logical_disk_*` (built-in) | [KCS-VALIDATED] -- thresholds calibration PARTIAL, see storage latency calibration note above |
| `BSODRisk_QGAServiceDown` | warning | 15m | config | 7128506 | `bsod_qga_service_running` (textfile) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_PagefilePressure` | warning | 15m | resource | 7132512 | `windows_pagefile_*` (built-in) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_DriverVersionOutdated` | warning | 0m | driver | 7141291 | `bsod_virtio_package_version` (textfile) | [KCS-VALIDATED] |
| `BSODRisk_LegacyDriverCollectorFallback` | info | 0m | driver | 7141291 | `bsod_virtio_package_version` / `bsod_virtio_driver_outdated` (textfile) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_CrashDumpDisabled` | warning | 0m | config | 7128506 | `bsod_crashdump_enabled` (textfile) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_GuestUnexpectedRestart` | warning | 2m | crash | 7141291 | `up{job=~"bsod-windows-exporter.*"}` + `kubevirt_vm_running_status_last_transition_timestamp_seconds` (virt-controller) | [GENERAL-KNOWLEDGE] -- proxy detection, known false positives on planned reboots within the 10m recency window |
| `BSODRisk_GuestCPUSaturation` | warning | 15m | cpu | 7132511 | `windows_cpu_time_total` (built-in) | [GENERAL-KNOWLEDGE] |
| `BSODRisk_GuestMemorySaturation` | warning | 15m | resource | 7132512 | `windows_memory_physical_free_bytes` / `windows_memory_physical_total_bytes` (built-in) | [GENERAL-KNOWLEDGE] |

Guest alerts show "no data" until `windows_exporter` with the BSOD textfile collector is deployed inside Windows VMs. `BSODRisk_GuestUnexpectedRestart` additionally requires the ServiceMonitor scraping the exporter itself (not just the textfile collector) since it keys off exporter `up`/`down` transitions, not a textfile metric. As of v0.17.0 it also requires `kubevirt_vm_running_status_last_transition_timestamp_seconds` to distinguish a genuine recent restart from an exporter that is merely unreachable (firewall, service stopped) -- this is a native virt-controller metric already scraped by the standard OCP Virt monitoring stack, not an additional guest-side dependency. `BSODRisk_GuestCPUSaturation`/`BSODRisk_GuestMemorySaturation` (R-46, Wave 7) use `windows_exporter`'s built-in `cpu`/`memory` collectors (enabled by default -- see `windows-exporter/install-windows-exporter.ps1`), not the BSOD textfile collector, so they only require the base exporter + ServiceMonitor, no additional guest-side script.

## Deployment

### Step 1: Deploy Recording Rules

Deploy recording rules **first** because the hypervisor alerts depend on the `bsod:vmi_disk_latency:avg_*` series they produce.

```bash
oc apply -f alerts/bsod-risk-recording-rules.yaml
```

### Step 2: Deploy Hypervisor Alerts

```bash
oc apply -f alerts/bsod-risk-prometheusrules.yaml
```

### Step 3: Deploy Guest Alerts (Optional)

Deploy only if `windows_exporter` is installed in Windows VMs:

```bash
oc apply -f alerts/bsod-risk-guest-alerts.yaml
```

See `windows-exporter/README.md` for installation instructions.

### Step 4: Verify

```bash
# Confirm all three PrometheusRules are created
oc get prometheusrule -n openshift-cnv -l app.kubernetes.io/component=bsod-detection

# Verify recording rules are producing data (requires running VMs with I/O)
oc -n openshift-monitoring exec -c prometheus prometheus-k8s-0 -- \
  promtool query instant http://localhost:9090 'bsod:vmi_disk_latency:avg_1h'

# Check for any firing alerts
oc -n openshift-monitoring exec -c prometheus prometheus-k8s-0 -- \
  promtool query instant http://localhost:9090 'ALERTS{alertname=~"BSODRisk_.*"}'
```

## Testing

The `tests.yaml` file contains 78 test cases covering all alerting and recording rules. Tests include both positive (alert fires) and negative (alert does not fire) scenarios.

### Run Tests Locally

`promtool` requires a standalone rules file (not a full `PrometheusRule` CR). Extract the rules first, then run tests:

```bash
cd alerts

# Extract rule groups from all three CRs into a single file
python3 -c "
import yaml, sys
groups = []
for f in ['bsod-risk-prometheusrules.yaml', 'bsod-risk-recording-rules.yaml', 'bsod-risk-guest-alerts.yaml']:
    with open(f) as fh:
        doc = yaml.safe_load(fh)
        groups.extend(doc['spec']['groups'])
yaml.dump({'groups': groups}, open('_rules_only.yaml', 'w'), default_flow_style=False)
"

# Run tests
promtool test rules tests.yaml

# Clean up
rm _rules_only.yaml
```

### Test Coverage

| Alert | Positive Tests | Negative Tests |
|-------|:---:|:---:|
| `BSODRisk_StorageLatencyElevated` | 1 | 2 |
| `BSODRisk_StorageLatencyHigh` | 1 | 3 |
| `BSODRisk_StorageLatencyBurst` | 1 | 1 |
| `BSODRisk_StorageLatencyTrending` | 1 | 1 |
| `BSODRisk_MemoryPressure` | 1 | 3 (low memory + non-Windows + missing os annotation) |
| `BSODRisk_GuestCrash` | 1 | 1 |
| `BSODRisk_HeterogeneousCPUMigration` | 1 | 3 |
| `BSODRisk_AMDNodeRequiresMicrocodeVerification` | 2 | 3 |
| `BSODRisk_EvictionBlocked` | 1 | 2 (evictable + missing os annotation) |
| `BSODRisk_GuestDiskLatencyHigh` | 1 | 1 |
| `BSODRisk_QGAServiceDown` | 1 | 1 |
| `BSODRisk_PagefilePressure` | 1 | 1 |
| `BSODRisk_DriverVersionOutdated` | 2 | 1 |
| `BSODRisk_LegacyDriverCollectorFallback` | 1 | 1 |
| `BSODRisk_CrashDumpDisabled` | 1 | 1 |
| `BSODRisk_GuestUnexpectedRestart` | 2 | 3 (unreachable-but-not-restarted regression guard added v0.17.0) |
| `BSODRisk_HostCPUContention` | 2 | 3 (busy-but-under-threshold, non-KubeVirt node scoping guard, brief spike below the `for:` window) |
| `BSODRisk_VirtLauncherCPUThrottled` | 1 | 3 (healthy throttle ratio, non-virt-launcher pod scoping guard, and the F-02 no-CPU-limit case where flat-zero CFS counters must stay silent) |
| `BSODRisk_GuestCPUSaturation` | 1 | 1 |
| `BSODRisk_GuestMemorySaturation` | 1 | 1 |
| `BSODRisk_FleetEvidenceIncomplete` | 1 | 2 (healthy value + not-yet-`for:`-window guard) |
| `BSODRisk_ExporterCollectionFailing` | 1 | 2 (healthy collection + not-yet-`for:`-window guard) |
| **Alert subtotal** | | **60** (`alertname:` occurrences) |
| Recording rules (non-zero IOPS / risk factor / compliance / fleet evidence ratio weighted-math + empty-input, etc.) | | **18** (`promql_expr_test:` blocks) |
| **Grand total** | | **78 test cases** |

This per-row breakdown predates several rule additions and individual row
counts are NOT re-verified on every change (only the subtotal/grand-total
below are kept current) -- `scripts/ci/validate-doc-counts.py` enforces the
top-level 11/7/9 rule counts (alerts/recording/guest-alerts) but does not
check this per-alert breakdown. Recompute the subtotal/grand-total after
adding a test with:

```bash
grep -c 'alertname:' tests.yaml          # alert_rule_test assertions
grep -c '^    promql_expr_test:' tests.yaml  # promql_expr_test blocks
```

### CI Integration

Tests run automatically in both `.gitlab-ci.yml` and `.github/workflows/ci.yaml` as the `validate-alerts` job. The CI pipeline also validates YAML syntax via `python3 -c "import yaml; yaml.safe_load(open(...))"`.

## Platform-Specific Notes

### OCP Version Requirements

| Feature | Minimum OCP | Notes |
|---------|-------------|-------|
| All hypervisor alerts | 4.12 | Base KubeVirt metrics available |
| `BSODRisk_GuestCrash` | **not yet available** | `kubevirt_vmi_guest_os_panic_total` has not shipped in any released HCO/CNV build as of 2026-07-10; the alert is a harmless no-op placeholder |
| `BSODRisk_AMDNodeRequiresMicrocodeVerification` | 4.14 (auto) | OCP < 4.14 requires manual kube-state-metrics label allowlist |
| `BSODRisk_StorageLatencyTrending` | 4.12 | Requires 24h of recording rule data for baseline |
| Guest alerts | 4.12 | Requires `windows_exporter` deployed in guest |

### kube-state-metrics Label Allowlist (OCP < 4.14)

The AMD microcode alert queries `kube_node_labels` for KubeVirt CPU-vendor labels. On OCP 4.14+, these are exposed by default (`nodes=[*]` allowlist). On older versions, configure manually:

```bash
oc -n openshift-monitoring edit configmap cluster-monitoring-config
```

Add under `data.config.yaml`:

```yaml
kubeStateMetrics:
  metricLabelsAllowlist:
    nodes:
      - cpu-vendor.node.kubevirt.io/*
      - cpu-family.node.kubevirt.io/*
      - cpu-model.node.kubevirt.io/*
```

### `os` Label Dependency (`BSODRisk_MemoryPressure` / `BSODRisk_EvictionBlocked`)

Both alerts filter on `kubevirt_vmi_info{os=~"windows|win.*"}`. This `os` label is populated **only from the `vm.kubevirt.io/os` annotation** (set by the mutating webhook for VMs created from a common-template/instance-type preference). It is not derived from the QEMU Guest Agent, and it is a different label than the guest-agent-sourced `guest_os_name` used elsewhere.

A Windows VM created without that annotation (raw manifest, Terraform/Ansible, or an MTV/Forklift plan without an OS hint) reports `os="<none>"`, so **both alerts silently never fire for it**. This is indistinguishable from "no problem" in Prometheus/Alertmanager.

See `docs/admin-runbook.md`'s Known limitations item 5 for the pre-flight
check and `oc patch` remediation (the nested `spec.template.metadata.annotations`
field).

Quick check:

```bash
oc get vmi <vm-name> -n <namespace> -o jsonpath='{.metadata.annotations.vm\.kubevirt\.io/os}{"\n"}'
# Empty or non-matching output = the two alerts above cannot fire for this VM.
```

### Limitations

- **No guest driver version in hypervisor metrics**: Cluster-side Prometheus cannot see VirtIO driver versions inside the guest. The `BSODRisk_DriverVersionOutdated` alert requires `windows_exporter` with the BSOD textfile collector.
- **`BSODRisk_MemoryPressure`/`BSODRisk_EvictionBlocked` depend on the `vm.kubevirt.io/os` annotation**: See "`os` Label Dependency" above. A missing annotation is a silent no-data condition, not a visible failure.
- **`evictionStrategy=None` not detectable from Prometheus**: The `evictable` label reports `true` for both `LiveMigrateIfPossible` and `None`. Use the BSOD audit script (Gate 6).
- **No histogram metrics**: KubeVirt exposes `_total` counters, not `_bucket` histograms. The recording rules derive averages from counter ratios.
- **`BSODRisk_DriverVersionOutdated` fallback path is a universal floor, not stream-aware**: The alert's *preferred* path uses `bsod_virtio_driver_outdated` from the textfile collector (a gauge computed in-guest from `virtio-win-thresholds.json` + OCP version) and is correctly stream-aware. The *fallback* path (used only when that gauge is absent with older/legacy textfile collectors) evaluates a single universal floor that cannot distinguish between streams. This is intentional: a genuinely stream-aware fallback would require an OCP-version/stream label on every legacy metric series. **Mitigation:** Deploy the current `bsod-textfile-collector.ps1` fleet-wide; treat any VM whose alert fires only via the legacy fallback as needing a collector upgrade. Gate 15 remains authoritative for full stream verdicts.

## Updating Rules

When modifying alert rules:

1. Edit the canonical source file in `alerts/`
2. Run `promtool test rules tests.yaml` locally
3. If the alert is embedded in the ACM policy, regenerate:
   ```bash
   python3 scripts/ci/validate-acm-policy.py --update
   ```
4. Apply changes: `oc apply -f alerts/<modified-file>.yaml`

Do not hand-edit PromQL inside the ACM policy -- always regenerate from canonical sources.

## Multi-Cluster Deployment

For environments managed by ACM 2.16+, all three PrometheusRule CRs are enforced via the governance policy in `acm/bsod-risk-policy.yaml`. See `acm/README.md` for details.

## Upstream Deconfliction (BSODRisk_GuestCrash vs VMNonRecoverableOSPanic)

Upstream KubeVirt merged a `VMNonRecoverableOSPanic` alert in
[kubevirt/kubevirt#18004](https://github.com/kubevirt/kubevirt/pull/18004)
(2026-06-30) that consumes the same `kubevirt_vmi_guest_os_panic_total` metric
as `BSODRisk_GuestCrash`. When this metric eventually ships in a CNV release,
both alerts will fire simultaneously unless one is suppressed.

**Recommended approach:** Use AlertManager `inhibit_rules` to suppress the
upstream alert when the BSOD-enriched alert is available (it provides
actionable remediation steps and pre-crash risk context):

```yaml
# alertmanager.yaml snippet
inhibit_rules:
  - source_matchers:
      - alertname = "BSODRisk_GuestCrash"
    target_matchers:
      - alertname = "VMNonRecoverableOSPanic"
    equal: ["name", "namespace"]
```

This suppresses `VMNonRecoverableOSPanic` for any VMI where
`BSODRisk_GuestCrash` is also firing, since the BSOD alert includes the same
information plus risk context and remediation actions.

**F14 (v0.17.0):** this design is now formalized (and `amtool`-validated in
CI) as `alerts/bsod-alertmanager-inhibit-rules.yaml`, shipped deliberately
INERT (YAML-commented) since the underlying metric hasn't shipped -- see that
file's header for the exact activation steps when it does.

**Interim (current state):** Neither alert fires today since
`kubevirt_vmi_guest_os_panic_total` does not exist on any shipping OCP Virt
release. The `BSODRisk_GuestUnexpectedRestart` proxy alert (based on
`windows_exporter` availability) provides crash detection today.

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| Alerts not firing | Verify PrometheusRules exist: `oc get prometheusrule -n openshift-cnv`. Check that metrics are populated via Thanos/Prometheus UI. |
| Storage latency alerts never fire | Deploy recording rules (`bsod-risk-recording-rules.yaml`). `BSODRisk_StorageLatencyTrending` requires 24h of baseline data. |
| `BSODRisk_GuestCrash` never fires | Expected on every shipping OCP Virt version -- the underlying metric has not shipped yet. Inspect virt-launcher logs for `GUEST_PANICKED`/`GUEST_CRASHLOADED` and attach them to the support case. |
| `BSODRisk_GuestUnexpectedRestart` never fires | Requires `windows_exporter` deployed with ServiceMonitor (job=`bsod-windows-exporter`). Verify `up` metric exists for the target. |
| `BSODRisk_AMDNodeRequiresMicrocodeVerification` never fires | On OCP < 4.14, configure the kube-state-metrics label allowlist (see above). |
| `BSODRisk_MemoryPressure`/`BSODRisk_EvictionBlocked` never fire for a known-Windows VM | Check the VMI's `vm.kubevirt.io/os` annotation -- it is likely missing or does not match `windows\|win.*`. |
| Guest alerts show "no data" | Deploy `windows_exporter` with the BSOD textfile collector. See `windows-exporter/README.md`. |
| `BSODRisk_MemoryPressure` fires on Linux VMs | Verify the VM's `os` label. The alert includes a `kubevirt_vmi_info{os=~"windows\|win.*"}` filter. |
| Recording rule produces NaN | Fixed -- the denominator guard (`> 0`) filters idle disks. Verify you have the latest `bsod-risk-recording-rules.yaml`. |
| `bsod:vm_risk_factor_count:gauge` shows no data | Requires `bsod-textfile-collector.ps1` deployed in guest VMs. The recording rule only emits series for VMs with the collector. |
| `promtool test rules` fails | Ensure `_rules_only.yaml` contains rule groups from all three CR files (hypervisor + recording + guest). |
| Alert annotation shows `{{ $labels.name }}` literally | The ACM policy requires `hub-templates: raw` and `disable-templates: true` annotations. See `acm/README.md`. |
