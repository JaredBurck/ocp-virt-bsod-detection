# Multi-Cluster BSOD Risk Aggregation -- ACM Observability Deployment Guide

## Overview

This guide covers deploying the ACM Observability custom metrics allowlist to enable fleet-wide BSOD risk visibility across all managed OpenShift clusters. By forwarding BSOD detection recording rules and guest-level metrics from each managed cluster to the hub's Thanos instance, operators gain a single pane of glass for monitoring Windows VM BSOD risk posture across the entire fleet.

ACM Observability uses a Thanos-based metric federation architecture: each managed cluster runs a metrics collector sidecar that selectively forwards allowed metrics to the hub's Thanos Receive endpoint. The custom allowlist ConfigMap (`observability-metrics-custom-allowlist`) tells those collectors which additional metrics to include beyond the default platform set.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ACM Hub Cluster                          │
│  ┌────────────────────────────────────────────────────────┐    │
│  │  Multicluster Observability Operator                    │    │
│  │  ┌──────────────┐  ┌────────────────┐  ┌───────────┐  │    │
│  │  │ Thanos       │  │ Observatorium  │  │ Grafana   │  │    │
│  │  │ Querier      │◄─┤ API            │◄─┤ Dashboard │  │    │
│  │  └──────┬───────┘  └────────────────┘  └───────────┘  │    │
│  └─────────┼──────────────────────────────────────────────┘    │
│            │ Thanos Receive                                     │
│  ┌─────────┼──────────────────────────────────────────────┐    │
│  │         ▼                                               │    │
│  │  observability-metrics-custom-allowlist (ConfigMap)      │    │
│  └─────────────────────────────────────────────────────────┘    │
└────────────┬────────────────────────────┬──────────────────────┘
             │                            │
    ┌────────▼────────┐         ┌────────▼────────┐
    │ Managed Cluster 1│         │ Managed Cluster 2│
    │ ┌──────────────┐ │         │ ┌──────────────┐ │
    │ │ Metrics      │ │         │ │ Metrics      │ │
    │ │ Collector    │ │         │ │ Collector    │ │
    │ ├──────────────┤ │         │ ├──────────────┤ │
    │ │ Prometheus   │ │         │ │ Prometheus   │ │
    │ │ Recording    │ │         │ │ Recording    │ │
    │ │ Rules        │ │         │ │ Rules        │ │
    │ ├──────────────┤ │         │ ├──────────────┤ │
    │ │ Windows VMs  │ │         │ │ Windows VMs  │ │
    │ │ (exporter)   │ │         │ │ (exporter)   │ │
    │ └──────────────┘ │         │ └──────────────┘ │
    └──────────────────┘         └──────────────────┘
```

The metrics collector on each managed cluster reads the allowlist from the hub and forwards matching series. The `cluster` label is automatically injected by the collector, enabling per-cluster filtering at the hub.

## Prerequisites

Before deploying the custom allowlist, confirm:

- **ACM 2.13+** with Multicluster Observability Operator installed and healthy on the hub cluster
- **`MultiClusterObservability` CR** deployed with object storage (S3/MinIO/ODF) configured for Thanos long-term storage
- **BSOD detection policy** deployed on managed clusters via `acm/bsod-risk-policy.yaml` -- this installs the PrometheusRule recording rules and alerts that produce the metrics being forwarded
- **At least one managed cluster** with Windows VMs running `windows_exporter` + `bsod-textfile-collector.ps1` (required for guest-level metrics in `uwl_metrics_list.yaml`; platform recording rules work without this)
- **`oc` CLI** authenticated to the hub cluster with `cluster-admin` privileges

## Deployment

### Step 1: Verify MCO is healthy

Confirm the Multicluster Observability Operator is running and ready:

```bash
oc get multiclusterobservability observability \
  -o jsonpath='{.status.conditions[*].type}{"\n"}{.status.conditions[*].status}'
```

Expected output should show `Ready True`. If the CR does not exist or is not ready, follow the [ACM Observability installation guide](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_management_for_kubernetes/2.12/html/observability/index) before proceeding.

### Step 2: Apply the custom metrics allowlist

```bash
oc apply -f acm/observability-metrics-custom-allowlist.yaml
```

This creates (or updates) the `observability-metrics-custom-allowlist` ConfigMap in the `open-cluster-management-observability` namespace. The MCO watches this ConfigMap and propagates the allowlist to all managed cluster metrics collectors.

### Step 3: Wait for metrics collector rollout

The metrics collector pods on each managed cluster will restart to pick up the new allowlist. This typically takes 2-5 minutes. Monitor rollout:

```bash
# On the hub, check the addon status for each managed cluster
oc get managedclusteraddons -A | grep observability

# On a managed cluster (if you have access), watch the collector pod
oc get pods -n open-cluster-management-addon-observability -w
```

### Step 4: Verify metrics are flowing to hub Thanos

Query the hub Thanos Querier to confirm metrics are arriving from managed clusters. You can use the OCP console's built-in Metrics page or query directly:

```bash
# Port-forward to Thanos Querier (if not using console)
oc -n open-cluster-management-observability port-forward svc/thanos-querier 9090:9090 &

# Test a platform recording rule
curl -s 'http://localhost:9090/api/v1/query?query=bsod:cluster_risk_summary:gauge' | jq '.data.result'

# Test a guest metric (requires windows_exporter on at least one VM)
curl -s 'http://localhost:9090/api/v1/query?query=bsod_virtio_driver_outdated' | jq '.data.result'
```

### Step 5: Deploy fleet dashboard (optional)

If a fleet-level Grafana dashboard is available, deploy its ConfigMap to the hub:

```bash
# The manifest declares metadata.namespace: open-cluster-management-observability
# (the namespace MCO watches for dashboard ConfigMaps), so no -n flag is needed.
# This previously passed `-n openshift-config-managed`, which contradicts the
# manifest and makes the command fail as written.
oc apply -f dashboards/bsod-risk-fleet-dashboard-configmap.yaml
```

### Step 6: Verify dashboard renders

Open the ACM Grafana instance (accessible from the ACM console under **Infrastructure > Clusters > Grafana**) and navigate to the BSOD Risk Fleet dashboard. All panels should populate with data from managed clusters within 5-10 minutes of allowlist deployment.

## Validation

Use these PromQL queries on the hub Thanos Querier to verify each metric category is being forwarded. All queries should return results with a `cluster` label identifying the source managed cluster.

### Platform recording rules

```promql
# Cluster-level risk summary (one series per managed cluster)
bsod:cluster_risk_summary:gauge

# Driver compliance ratio (1.0 = all compliant)
bsod:cluster_driver_compliance:ratio

# CPU model heterogeneity count
bsod:cluster_cpu_model_count:gauge
```

### Per-VM disk latency

```promql
# 1-hour average disk latency by VM and drive
bsod:vmi_disk_latency:avg_1h

# 24-hour average (use for trend analysis)
bsod:vmi_disk_latency:avg_24h
```

### Per-VM risk factors

```promql
# Risk factor count per VM (0-3 range)
bsod:vm_risk_factor_count:gauge

# Hub-side recording rule: active alert count per cluster
bsod:cluster_alert_count:gauge
```

### Guest-level metrics (user workload)

```promql
# Driver outdated flag (1 = outdated, 0 = current)
bsod_virtio_driver_outdated

# VirtIO package version (label value)
bsod_virtio_package_version

# IoTimeoutValue from guest registry
bsod_io_timeout_value

# Crash dump configuration (1 = enabled)
bsod_crashdump_enabled
```

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| No BSOD metrics appear on hub Thanos | ConfigMap in wrong namespace or MCO not watching | Verify ConfigMap is in `open-cluster-management-observability` namespace. Check `oc get configmap observability-metrics-custom-allowlist -n open-cluster-management-observability`. |
| Platform recording rules absent on managed cluster | ACM policy not compliant | Run `oc get policy bsod-risk-detection -n open-cluster-management-policies` on the hub. Check `status.compliant` per managed cluster. Remediate non-compliant clusters. |
| Guest metrics (`bsod_virtio_*`) missing | `windows_exporter` or textfile collector not deployed in VM | Verify `windows_exporter` is running in the guest (`Get-Service windows_exporter`). Check textfile collector output in `C:\ProgramData\windows_exporter\textfile_inputs\`. See `windows-exporter/README.md`. |
| High cardinality warning from MCO | Too many per-VM disk latency series | For large fleets (500+ VMs), consider forwarding only the cluster-level aggregates (`bsod:cluster_risk_summary:gauge`, `bsod:cluster_driver_compliance:ratio`) and removing per-VM disk latency series from the allowlist. |
| Dashboard shows "No data" for all panels | Thanos Querier datasource misconfigured or `cluster` label missing | Verify the Grafana datasource URL points to the Thanos Querier service. Confirm `cluster` label is present on forwarded metrics: `bsod:cluster_risk_summary:gauge{cluster!=""}`. |
| Metrics appear but with stale timestamps | Metrics collector not restarted after ConfigMap update | Delete the metrics-collector pod on the affected managed cluster to force a restart: `oc delete pod -n open-cluster-management-addon-observability -l component=metrics-collector`. |
| `uwl_metrics_list.yaml` metrics not forwarded | User workload monitoring not enabled on managed cluster | Enable user workload monitoring on the managed cluster: ensure `enableUserWorkload: true` in `cluster-monitoring-config` ConfigMap in `openshift-monitoring`. |

## Cardinality Planning

Estimate the number of Prometheus series forwarded per managed cluster based on the Windows VM count. Use this table to assess the impact on hub Thanos storage and query performance.

| Windows VMs per cluster | Platform rules | Per-VM disk latency (avg 3 disks) | Per-VM risk/guest | Total series (approx.) |
|------------------------:|---------------:|-----------------------------------:|------------------:|-----------------------:|
| 10                      | 3              | 30                                 | 70                | ~100                   |
| 50                      | 3              | 150                                | 350               | ~500                   |
| 100                     | 3              | 300                                | 700               | ~1,000                 |
| 500                     | 3              | 1,500                              | 3,500             | ~5,000                 |

Notes:

- Platform recording rules (`bsod:cluster_risk_summary:gauge`, `bsod:cluster_driver_compliance:ratio`, `bsod:cluster_cpu_model_count:gauge`) produce exactly 3 series per cluster regardless of VM count.
- Per-VM disk latency assumes an average of 3 drives per VM (OS disk + 2 data disks). Actual count depends on VM configuration.
- Per-VM risk/guest metrics count assumes `windows_exporter` + `bsod-textfile-collector.ps1` deployed on all Windows VMs (7 series per VM: 6 guest metrics + 1 risk factor count).
- The hub-side recording rule `bsod:cluster_alert_count:gauge` adds 1 series per managed cluster.
- For fleets exceeding 500 Windows VMs per cluster, consider removing per-VM disk latency from the allowlist and relying on the recording-rule aggregates only.

## MCOA vs Legacy Architecture

ACM Observability can be deployed in two architectures:

### Legacy (MCO addon per managed cluster)

The original architecture deploys a standalone metrics collector addon on each managed cluster. The collector reads from the managed cluster's Prometheus and writes to the hub's Thanos Receive. This is the default for ACM 2.9 through 2.11.

- Custom allowlist: `observability-metrics-custom-allowlist` ConfigMap in `open-cluster-management-observability`
- User workload metrics: `uwl_metrics_list.yaml` key in the same ConfigMap
- Collector namespace on managed cluster: `open-cluster-management-addon-observability`

### MCOA (Multicluster Observability Addon)

Starting with ACM 2.12, the Multicluster Observability Addon (MCOA) consolidates multiple addon agents into a single FluentBit + metrics pipeline. MCOA uses the same allowlist ConfigMap format, so this deployment guide applies to both architectures.

- Custom allowlist: same `observability-metrics-custom-allowlist` ConfigMap (compatible)
- MCOA unifies logging, metrics, and tracing collection
- Recommended for new ACM installations on ACM 2.12+

**Recommendation**: For new ACM installations, use the MCOA architecture. The custom metrics allowlist ConfigMap is compatible with both architectures -- no changes required when migrating from legacy to MCOA.

## Security Considerations

- **Read-only data**: All forwarded metrics are observability data (counters, gauges, ratios). No credentials, secrets, or personally identifiable information is included in any BSOD detection metric.
- **Label values**: Guest-level metrics include driver version strings and registry values sourced from Windows VMs. These are sanitized by `bsod-textfile-collector.ps1` (escaped via `ConvertTo-EscapedPrometheusLabelValue`) before export.
- **Network path**: Metrics flow from managed cluster Prometheus to hub Thanos Receive over the ACM addon communication channel, which uses mutual TLS by default.
- **RBAC**: The custom allowlist ConfigMap requires `cluster-admin` on the hub cluster to create or modify. Managed cluster metrics collectors run with their own ServiceAccount scoped to the addon namespace.
- **No write-back**: The hub cannot push configuration or execute commands on managed clusters through the observability channel. It is strictly a pull/forward mechanism for metrics.
