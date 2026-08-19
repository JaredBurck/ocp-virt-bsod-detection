# Grafana Dashboard Deployment Guide for BSOD Detection

## Overview

This guide covers deploying BSOD Risk Grafana dashboards on OpenShift. Two dashboards are available:

1. **BSOD Risk Overview** -- single-cluster view of `BSODRisk_*` alerts, per-VM risk heatmaps, fleet readiness, storage latency trends, memory pressure, and VirtIO driver distribution
2. **BSOD Risk Fleet Overview** -- multi-cluster ACM hub view aggregating risk scores, driver compliance, and firing alerts across managed clusters

Three deployment methods are available:

1. **Grafana Operator v5** (recommended) -- full-featured Grafana with OpenShift OAuth, persistent dashboards, and operator-managed lifecycle
2. **OCP Console ConfigMap** -- lightweight, no operator required, uses the built-in OCP console Grafana
3. **ACM Observability ConfigMap** -- for multi-cluster fleet dashboard on the ACM hub (uses ACM's Grafana instance)

A fourth, optional path exists for environments already running the Cluster Observability Operator (COO 1.5+): import `bsod-risk-overview.json` into COO's native Perses dashboards instead of standing up Grafana. This does **not** require RHACM. See `[coo/README.md](../coo/README.md)`'s "Part A: Single-Cluster Capabilities" (A2) for the migration steps and known limitations -- this is an alternative to Method 1, not a replacement; the canonical dashboard source of truth is still this directory's JSON either way.

## Components

| File | Purpose |
|------|---------|
| `grafana-5.24.0.yaml` | Grafana Operator installation: Namespace, Subscription, ServiceAccount, Secrets, PVC, Grafana instance with oauth-proxy |
| `bsod-risk-grafanadashboard-cr.yaml` | GrafanaDashboard CR (for Grafana Operator) |
| `bsod-risk-dashboard-configmap.yaml` | ConfigMap with dashboard JSON (for OCP built-in Grafana) |
| `bsod-risk-overview.json` | Raw single-cluster dashboard JSON (source of truth -- see [Keeping JSON and YAML in Sync](#keeping-json-and-yaml-in-sync)) |
| `bsod-risk-fleet-overview.json` | Raw multi-cluster fleet dashboard JSON (source of truth for fleet ConfigMaps) |
| `bsod-risk-fleet-dashboard-configmap.yaml` | Fleet dashboard ConfigMap for ACM Observability Grafana (`open-cluster-management-observability` namespace) |
| `bsod-risk-fleet-console-configmap.yaml` | Fleet dashboard ConfigMap for OCP Console Grafana (`openshift-config-managed` namespace) |

## Prerequisites

Before deploying, confirm:

- cluster-admin or equivalent RBAC
- `community-operators` CatalogSource available (verify: `oc get catalogsource -n openshift-marketplace`)
- PrometheusRule alerts deployed (`alerts/bsod-risk-prometheusrules.yaml` and `alerts/bsod-risk-guest-alerts.yaml`)
- Recording rules deployed (`alerts/bsod-risk-recording-rules.yaml`) -- required for latency trend, CPU heterogeneity, and risk factor panels
- For guest-metric panels (pagefile pressure, driver versions): `windows_exporter` deployed in Windows VMs (see `windows-exporter/README.md`)

## Dashboard Panels (Single-Cluster)

| Section | Panel | Data Source |
|---------|-------|-------------|
| Alert Overview | Total Firing Alerts | `count(ALERTS{alertname=~"BSODRisk_.*", alertstate="firing"})` |
| Alert Overview | Firing Alerts by Severity | `ALERTS` counted by `severity` label |
| Per-VM Risk | Per-VM Active BSOD Alerts | `ALERTS` counted by `name`/`namespace` |
| Node & Cluster Alerts | Nodes with Active Risk Alerts | `ALERTS` (node-scoped, `name=""`) counted by `node` |
| Node & Cluster Alerts | All Firing Alerts (Detail) | `ALERTS` table with alert, severity, namespace, VM, node, status columns |
| Node & Cluster Alerts | Node CPU Vendor Distribution | `kube_node_labels` with KubeVirt `cpu-vendor` labels (OCP 4.14+ default) |
| Node & Cluster Alerts | Cluster CPU Heterogeneity Status | `bsod:cluster_cpu_model_count:gauge` (recording rule) |
| Fleet Readiness | VMs with Active Alerts by Namespace | `ALERTS` VM-scoped count by `namespace` |
| Fleet Readiness | Fleet Summary | `kubevirt_vmi_info` (total running) + `ALERTS` (at-risk count) |
| Storage Latency | VM Disk Read Latency (avg per I/O) | `kubevirt_vmi_storage_read_times_seconds_total` / `kubevirt_vmi_storage_iops_read_total` |
| Storage Latency | Storage Latency Trend (1h / 24h ratio) | `bsod:vmi_disk_latency:avg_1h` / `bsod:vmi_disk_latency:avg_24h` (recording rules) |
| Memory Pressure | Windows VM Memory Utilization (Guest / Domain) | `kubevirt_vmi_memory_used_bytes` / `kubevirt_vmi_memory_domain_bytes` |
| Memory Pressure | Pagefile Pressure (windows_exporter) | `windows_pagefile_limit_bytes` - `windows_pagefile_free_bytes` (windows_exporter) |
| Guest CPU & Memory Saturation (windows_exporter) | Guest CPU Utilization (windows_exporter) | `windows_cpu_time_total` (windows_exporter built-in `cpu` collector) |
| Guest CPU & Memory Saturation (windows_exporter) | Guest Physical Memory Utilization (windows_exporter) | `windows_memory_physical_free_bytes` / `windows_memory_physical_total_bytes` (windows_exporter built-in `memory` collector) |
| Driver Version Distribution | VirtIO Driver Versions by VM (windows_exporter) | `bsod_virtio_driver_version` (windows_exporter textfile collector) |
| Crash Detection & Risk Context | Per-VM Risk Factor Count | `bsod:vm_risk_factor_count:gauge` (recording rule) |
| Crash Detection & Risk Context | Crash Events (Proxy: Exporter Down) | `up{job=~"bsod-windows-exporter.*"}` + `BSODRisk_GuestUnexpectedRestart` alerts |

## Method 1: Grafana Operator (Recommended)

### Step 1: Generate Secrets

```bash
COOKIE_SECRET=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode()[:32])")
echo "Cookie secret: $COOKIE_SECRET"

GRAFANA_ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
echo "Grafana admin password: $GRAFANA_ADMIN_PASSWORD"
```

Edit `grafana-5.24.0.yaml` and replace these placeholders:

| Placeholder | Location | Replace With |
|-------------|----------|-------------|
| `<COOKIE_SECRET>` | `grafana-proxy-cookie` Secret | The cookie secret value generated above |
| `<GRAFANA_ADMIN_PASSWORD>` | Grafana CR `config.security.admin_password` | The admin password generated above |
| `<GRAFANA_ROUTE>` | Grafana CR `server.root_url` | The expected route hostname (e.g., `bsod-grafana-route-grafana.apps.<cluster-domain>`) |

Store the admin password in your team's secret manager. It is not needed for day-to-day use (see authentication flow below) but is required for break-glass access.

**Authentication model:** Normal users authenticate via OpenShift OAuth through the `oauth-proxy` sidecar (`disable_login_form: "true"`) and are auto-provisioned with the `Viewer` org role. They never see or need the admin password. The `admin_user`/`admin_password` pair is only a local break-glass credential for direct Grafana API/CLI access. To grant a specific user `Admin` rights, use the Grafana UI (Administration > Users) or API -- do not change `auto_assign_org_role` back to `Admin` fleet-wide.

### Step 2: Apply the Grafana Stack

The manifest contains both the OLM Subscription and the Grafana CR. Because OLM needs time to install the operator and register CRDs, a single `oc apply` fails on the Grafana CR with *"no matches for kind Grafana"*. Apply in two phases:

```bash
# Phase 1: Create namespace, operator subscription, RBAC, secrets, PVC
oc apply -f dashboards/grafana-5.24.0.yaml || true

# Phase 2: Wait for the Grafana CRD, then re-apply to create the Grafana CR
oc wait --for=condition=Established \
  crd/grafanas.grafana.integreatly.org --timeout=120s
oc apply -f dashboards/grafana-5.24.0.yaml
```

This creates:

1. `grafana` Namespace
2. OperatorGroup + Subscription (installs Grafana Operator via OLM)
3. ServiceAccount with OAuth redirect annotation
4. `grafana-sa-token` Secret (long-lived SA token, auto-populated by OCP)
5. `grafana-proxy-cookie` Secret (session cookie for oauth-proxy)
6. ClusterRoleBinding granting `cluster-monitoring-view` to the SA
7. PersistentVolumeClaim for Grafana database (persists datasource config across restarts)
8. Grafana instance with oauth-proxy sidecar + PVC mount

### Step 3: Create the Bearer-Token Secret

Wait approximately 30 seconds after the apply for the `grafana-sa-token` Secret to be populated, then create a derived secret with the `Bearer` prefix:

```bash
TOKEN=$(oc get secret grafana-sa-token -n grafana -o jsonpath='{.data.token}' | base64 -d)
oc create secret generic grafana-sa-bearer-token -n grafana \
  --from-literal=bearer-token="Bearer ${TOKEN}" \
  --dry-run=client -o yaml | oc apply -f -
```

**Why this is required:** The Grafana datasource `Authorization` header requires the full `Bearer <token>` string, not just the raw JWT.

**Safe to re-run:** `--dry-run=client -o yaml | oc apply -f -` makes this idempotent (e.g., if the SA token is rotated).

### Step 4: Create the Prometheus Datasource

Wait for the Grafana pod to become Ready (2/2 containers), then create the datasource via the Grafana API:

```bash
oc wait --for=condition=Available deploy/bsod-grafana-deployment -n grafana --timeout=120s

# Read values set in Step 1 / Step 3 at run time -- never hardcode them
ADMIN_PASSWORD=$(oc get grafana bsod-grafana -n grafana -o jsonpath='{.spec.config.security.admin_password}')
BEARER_TOKEN=$(oc get secret grafana-sa-bearer-token -n grafana -o jsonpath='{.data.bearer-token}' | base64 -d)

# L2 (v0.16.0): trust the cluster's own service CA explicitly instead of
# "tlsSkipVerify":true. The route is in-cluster and thanos-querier presents
# a certificate signed by that CA, which every pod can already validate --
# skipping verification would also silently accept an interposed endpoint
# on the pod network. See dashboards/grafana-5.24.0.yaml's identical fix.
SERVICE_CA=$(oc get configmap openshift-service-ca.crt -n grafana \
  -o jsonpath='{.data.service-ca\.crt}')

oc exec -n grafana deploy/bsod-grafana-deployment -c grafana -- \
  curl -s -X POST --netrc-file <(printf 'machine localhost login admin password %s\n' "$ADMIN_PASSWORD") \
    -H "Content-Type: application/json" \
    http://localhost:3000/api/datasources \
    -d "{\"name\":\"Prometheus\",\"type\":\"prometheus\",\"access\":\"proxy\",
         \"url\":\"https://thanos-querier.openshift-monitoring.svc.cluster.local:9091\",
         \"isDefault\":true,
         \"jsonData\":{\"httpHeaderName1\":\"Authorization\",\"timeInterval\":\"30s\",
                        \"tlsAuthWithCACert\":true},
         \"secureJsonData\":{\"httpHeaderValue1\":\"${BEARER_TOKEN}\",
                              \"tlsCACert\":\"${SERVICE_CA}\"}}"
```

Fetching both values at run time means this step never requires a real secret committed to git and is safe to copy-paste against any cluster where you have already substituted `<GRAFANA_ADMIN_PASSWORD>` per Step 1.

**Keeping this in sync:** this is the same datasource-creation example as `dashboards/grafana-5.24.0.yaml`'s header comment (used for the fleet dashboard's Grafana instance). If you change the TLS trust approach here, change it there too -- `scripts/ci/validate-shared-thresholds.py`/`validate-dashboard-configmap.py` do not currently check example-doc TLS wording, so this pair is only kept in sync by convention.

**Why not use the GrafanaDatasource CR?** The Grafana Operator v5's `valuesFrom` mechanism for `secureJsonData` is broken -- it reports success but does not inject the Bearer token into Grafana's database. The API-based approach with the PVC-backed database ensures the token persists across pod restarts.

### Step 5: Deploy the Dashboard

```bash
oc apply -f dashboards/bsod-risk-grafanadashboard-cr.yaml
```

### Step 6: Verify

```bash
# Check Grafana and dashboard resources
oc get grafana,grafanadashboard -n grafana

# Check datasource works (secureJsonFields must include httpHeaderValue1)
ADMIN_PASSWORD=$(oc get grafana bsod-grafana -n grafana -o jsonpath='{.spec.config.security.admin_password}')
DS_UID=$(oc exec -n grafana deploy/bsod-grafana-deployment -c grafana -- \
  curl -s --netrc-file <(printf 'machine localhost login admin password %s\n' "$ADMIN_PASSWORD") http://localhost:3000/api/datasources \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['uid'])")
oc exec -n grafana deploy/bsod-grafana-deployment -c grafana -- \
  curl -s --netrc-file <(printf 'machine localhost login admin password %s\n' "$ADMIN_PASSWORD") "http://localhost:3000/api/datasources/uid/${DS_UID}" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('secureJsonFields:', d.get('secureJsonFields',{}))"

# Get the dashboard URL
oc get route bsod-grafana-route -n grafana -o jsonpath='https://{.spec.host}/d/bsod-risk-overview'
```

### Step 7: Verify Data Flow

After Step 6 confirms the datasource is configured, verify that Prometheus has the metrics the dashboard expects. Empty panels usually indicate a missing prerequisite, not a datasource problem.

```bash
# Hypervisor metrics (should return data if any VMIs are running)
oc exec -n openshift-monitoring prometheus-k8s-0 -c prometheus -- \
  curl -sg 'http://localhost:9090/api/v1/query?query=count(kubevirt_vmi_info)' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('kubevirt_vmi_info:', r['data']['result'])"

# Alert metrics (empty result is normal if no alerts are firing)
oc exec -n openshift-monitoring prometheus-k8s-0 -c prometheus -- \
  curl -sg 'http://localhost:9090/api/v1/query?query=count(ALERTS{alertname=~"BSODRisk_.*"})' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('BSODRisk alerts:', r['data']['result'])"

# Recording rules (empty means recording rules not deployed or not yet evaluated)
oc exec -n openshift-monitoring prometheus-k8s-0 -c prometheus -- \
  curl -sg 'http://localhost:9090/api/v1/query?query=bsod:cluster_cpu_model_count:gauge' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('CPU heterogeneity:', r['data']['result'])"

# Guest metrics -- only present if windows_exporter is deployed and scraped
oc exec -n openshift-monitoring prometheus-k8s-0 -c prometheus -- \
  curl -sg 'http://localhost:9090/api/v1/query?query=count(bsod_virtio_driver_version)' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('virtio driver metrics:', r['data']['result'])"
```

If any check returns an unexpected empty result, see the Troubleshooting table below for the matching panel.

## Method 2: OCP Console ConfigMap

For environments without the Grafana Operator, deploy the dashboard as a ConfigMap that the OCP console's built-in Grafana discovers:

```bash
oc apply -f dashboards/bsod-risk-dashboard-configmap.yaml
```

The ConfigMap is labeled with `console.openshift.io/dashboard: "true"` and deploys to `openshift-config-managed`. The dashboard appears in the OCP console under **Observe > Dashboards**.

**Limitations of this method:**
- No persistent storage
- Limited plugin support
- No OAuth-proxy integration
- Variables and some panel types do not render identically to the Grafana Operator deployment

## Method 3: ACM Fleet Dashboard (Multi-Cluster)

For ACM hub clusters with `open-cluster-management-observability` deployed, the fleet dashboard aggregates BSOD risk data across all managed clusters via Thanos Querier.

**Prerequisites (in addition to the general prerequisites above):**

- ACM 2.16+ with Observability enabled
- BSOD PrometheusRules and recording rules deployed on each managed cluster
- Thanos Querier aggregating metrics from managed clusters

### Deploy to ACM Observability Grafana

```bash
oc apply -f dashboards/bsod-risk-fleet-dashboard-configmap.yaml
```

This deploys the fleet dashboard ConfigMap to `open-cluster-management-observability` with the `grafana-custom-dashboard: "true"` label. ACM's Grafana instance discovers it automatically.

### Deploy to OCP Console (Alternative)

```bash
oc apply -f dashboards/bsod-risk-fleet-console-configmap.yaml
```

This deploys the same fleet dashboard to `openshift-config-managed` for the OCP console Grafana. Same limitations as Method 2 apply.

### Fleet Dashboard Panels

| Section | Panel | Data Source |
|---------|-------|-------------|
| Fleet Risk Summary | Total Managed Clusters | `count(bsod:cluster_risk_summary:gauge)` |
| Fleet Risk Summary | Fleet Risk Score (Total) | `sum(bsod:cluster_risk_summary:gauge)` |
| Fleet Risk Summary | Fleet Driver Compliance | `avg(bsod:cluster_driver_compliance:ratio)` |
| Per-Cluster Risk Heatmap | Cluster Risk Scores | `bsod:cluster_risk_summary:gauge` by cluster |
| Per-Cluster Risk Heatmap | Driver Compliance by Cluster | `bsod:cluster_driver_compliance:ratio` by cluster |
| Alert Summary | Firing BSOD Alerts by Cluster | `ALERTS{alertname=~"BSODRisk_.*"}` by cluster + alertname |
| Alert Summary | Total Firing Alerts per Cluster | `ALERTS` count by cluster |
| Top Risk VMs (Global) | Highest Risk VMs | `topk(10, bsod:vm_risk_factor_count:gauge)` |
| Top Risk VMs (Global) | VMs with Outdated Drivers | `bsod_virtio_driver_outdated == 1` |
| Storage Latency (Cross-Cluster) | High Latency VMs Across Fleet | `bsod:vmi_disk_latency:avg_1h > 1` |

## Architecture

```
┌─────────────────────────────┐
│   Grafana (oauth-proxy)      │
│   namespace: grafana         │
│                              │
│  ┌─────────────────────────┐ │
│  │ PVC: grafana-data (1Gi) │ │    Persists datasource config
│  │ -> /var/lib/grafana      │ │    (Bearer token survives restarts)
│  └─────────────────────────┘ │
│                              │
│  ┌─────────────────────────┐ │
│  │ Prometheus Datasource   │ │
│  │ -> Thanos Querier       │─┼──> thanos-querier.openshift-monitoring.svc:9091
│  │    (Bearer token)       │ │       │
│  └─────────────────────────┘ │       │
│                              │       ▼
│  ┌─────────────────────────┐ │   ┌────────────────────┐
│  │ GrafanaDashboard CR     │ │   │ Prometheus          │
│  │ bsod-risk-overview      │ │   │ (platform + user)   │
│  └─────────────────────────┘ │   │                     │
└─────────────────────────────┘   │ ┌─────────────────┐ │
                                   │ │ PrometheusRules  │ │
                                   │ │ BSODRisk_*       │ │
                                   │ └─────────────────┘ │
                                   │                     │
                                   │ ┌─────────────────┐ │
                                   │ │ ServiceMonitor   │ │
                                   │ │ windows-exporter │ │
                                   │ └────────┬────────┘ │
                                   └──────────┼──────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │ Per-VM Services       │
                                   │ bsod-test namespace   │
                                   │ -> virt-launcher:9182 │
                                   │ -> windows_exporter   │
                                   └──────────────────────┘
```

## Authentication Flow

The Grafana instance uses the standard OpenShift oauth-proxy pattern:

1. User accesses the Grafana Route (HTTPS, reencrypt TLS)
2. `oauth-proxy` sidecar intercepts and redirects to OpenShift OAuth
3. User authenticates with OpenShift credentials
4. `oauth-proxy` passes `X-Forwarded-User` header to Grafana
5. Grafana's `auth.proxy` trusts the header and auto-creates the user with the `Viewer` org role

The datasource authenticates to Thanos Querier using the `grafana-sa` ServiceAccount token via a custom `Authorization` HTTP header. The SA has `cluster-monitoring-view` ClusterRole, granting read access to all Prometheus metrics.

## Keeping JSON and YAML in Sync

The `bsod-risk-overview.json` and `bsod-risk-fleet-overview.json` files are the sources of truth. All deployment YAML files embed copies of this JSON inline. After editing either JSON file, regenerate all artifacts with a single command:

```bash
./scripts/generate-dashboard-artifacts.sh
```

This regenerates:

1. `dashboards/bsod-risk-dashboard-configmap.yaml` (OCP Console)
2. `dashboards/bsod-risk-grafanadashboard-cr.yaml` (Grafana Operator)
3. Dashboard section in `acm/bsod-risk-policy.yaml` (ACM enforcement)
4. `dashboards/bsod-risk-fleet-dashboard-configmap.yaml` (MCO Grafana, byte-identical embed)
5. `dashboards/bsod-risk-fleet-console-configmap.yaml` (OCP Console -- intentionally converts three table panels to stat/bargauge for console compatibility)

**Do not edit the YAML files directly** -- they will be overwritten on the next script run. Always edit the source JSON, then run the script.

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| Dashboard shows "Unauthorized" or no data | Datasource token not injected. Re-run Step 4 to create the datasource via the API. The PVC ensures this only needs to be done once. |
| `secureJsonFields` is empty `{}` | The Bearer token was not injected during datasource creation. Delete the datasource via Grafana API and re-run Step 4. |
| Grafana pod CrashLoopBackOff | Verify `<COOKIE_SECRET>` placeholder was replaced in `grafana-proxy-cookie` Secret. Verify `<GRAFANA_ROUTE>` was replaced in the Grafana CR, and that the `grafana-admin-credentials` Secret exists (R-20 moved the admin password out of the CR into that Secret). |
| `no matches for kind "Grafana"` on first apply | Expected -- OLM has not registered CRDs yet. Wait for CRD and re-apply (see Step 2 two-phase instructions). |
| Driver Compliance shows `N/A` | **Correct, not a fault.** `bsod:cluster_driver_compliance:ratio` is absent when *no* VM reports `bsod_virtio_driver_outdated` -- i.e. the windows_exporter textfile collector is not deployed anywhere yet. Distinguish three states: **absent/`N/A`** = nothing assessed; **`0`** = every reporting VM is outdated; **`1`** = every reporting VM is compliant. Until R-39 (v0.19.0) the rule ended in `or vector(1)`, so this panel showed a fabricated **100% compliance** on exactly the clusters that had never been instrumented. |
| Operator not installing | Verify `community-operators` CatalogSource is healthy: `oc get catalogsource -n openshift-marketplace`. |
| `grafana-operator.v5.24.0` CSV shows `Failed` / `TooManyOperatorGroups` in Installed Operators | Live-cluster validated (2026-08-02): happens when the Grafana Operator was already installed in this namespace before applying `grafana-5.24.0.yaml` (e.g. via the console UI), which auto-creates its own `OperatorGroup` -- this file's `OperatorGroup` becomes a second one in the same namespace, and OLM can't auto-resolve CSV scope with two present. Check `oc get operatorgroup -n grafana`; if there are two, `oc delete operatorgroup grafana-operator-group -n grafana` (the one this file creates) and confirm `oc get csv grafana-operator.v5.24.0 -n grafana` returns to `Succeeded`. The running Grafana instance/pods are not affected by this while it's happening -- only OLM's CSV reconciliation is. |
| Dashboard not appearing | Verify GrafanaDashboard CR's `instanceSelector` matches the Grafana instance labels (`dashboards: bsod-grafana`). If pod restarted, delete and re-apply the GrafanaDashboard CR. |
| Guest-metric panels empty | Deploy `windows_exporter` with the BSOD textfile collector inside Windows VMs. See `windows-exporter/README.md`. |
| Storage latency panels empty | Deploy recording rules: `oc apply -f alerts/bsod-risk-recording-rules.yaml`. The 24h baseline needs 24h of data before showing results. |
| CPU heterogeneity panel shows "Recording rule not evaluated" | Deploy recording rules: `oc apply -f alerts/bsod-risk-recording-rules.yaml`. Verify with: `oc exec -n openshift-monitoring prometheus-k8s-0 -c prometheus -- curl -sg 'http://localhost:9090/api/v1/query?query=bsod:cluster_cpu_model_count:gauge'`. |
| Risk Factor Count panel empty | Deploy recording rules and verify `windows_exporter` metrics are being scraped. The recording rule `bsod:vm_risk_factor_count:gauge` depends on guest-side metrics. |
| VM variable dropdown empty | The variable queries `label_values(kubevirt_vmi_info, name)` which requires running VMs. Verify VMIs are up: `oc get vmi -A`. |
| ConfigMap dashboard not visible in OCP console | Verify the ConfigMap is in `openshift-config-managed` namespace and has the `console.openshift.io/dashboard: "true"` label. |
| Fleet dashboard empty on ACM hub | Verify `bsod:cluster_risk_summary:gauge` recording rule is deployed on managed clusters and metrics are flowing to the hub's Thanos Querier. |
