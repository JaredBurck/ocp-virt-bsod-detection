# ACM Policy Deployment Guide for BSOD Detection

## Overview

This guide covers deploying the BSOD Detection Framework across multiple OpenShift clusters using Red Hat Advanced Cluster Management (ACM) governance policies. The ACM policy distributes PrometheusRule alerts, recording rules, and the Grafana dashboard ConfigMap to all CNV-enabled managed clusters. It ships in `inform` mode -- see Step 4 for the recommended `inform` -> single-cluster `enforce` -> fleet rollout.

## Components


| File                    | Purpose                                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| `bsod-risk-policy.yaml` | Policy with 4 ConfigurationPolicy templates (hypervisor alerts, recording rules, dashboard, guest alerts) |
| `placement-rule.yaml`   | ManagedClusterSetBinding, Placement, and PlacementBinding for cluster targeting                           |




### Policy Structure

The `bsod-risk-detection` Policy contains four `ConfigurationPolicy` templates:


| ConfigurationPolicy           | Enforced Object                                                        | Remediation | Severity |
| ----------------------------- | ---------------------------------------------------------------------- | ----------- | -------- |
| `bsod-risk-prometheusrule`    | PrometheusRule `bsod-risk-alerts` (13 hypervisor alerts)               | inform*     | high     |
| `bsod-risk-recording-rules`   | PrometheusRule `bsod-risk-recording-rules` (11 recording rules)        | inform*     | high     |
| `bsod-risk-grafana-dashboard` | ConfigMap `bsod-risk-grafana-dashboard` (Grafana dashboard JSON)       | inform*     | low      |
| `bsod-risk-guest-alerts`      | PrometheusRule `bsod-risk-guest-alerts` (9 guest-metric alerts)        | inform*     | medium   |


\* Ships as `inform`; switch to `enforce` after a single-cluster soak (see Step 4). All objects target `openshift-cnv` on each managed cluster using `complianceType: musthave`.

## Prerequisites

Before deploying, confirm:

- ACM 2.16+ installed on the hub cluster
- `oc` CLI authenticated to the hub cluster with cluster-admin
- Managed clusters labeled for targeting (see Cluster Targeting below)
- `open-cluster-management-policies` namespace exists on the hub



### ACM 2.16+ API Requirements

The policy manifests use ACM 2.16+ APIs:


| Resource                   | API Version                                  | Notes                                                  |
| -------------------------- | -------------------------------------------- | ------------------------------------------------------ |
| `ManagedClusterSetBinding` | `cluster.open-cluster-management.io/v1beta2` | v1beta1 deprecated in ACM 2.16                         |
| `Placement`                | `cluster.open-cluster-management.io/v1beta1` | Standard placement API                                 |
| `PlacementBinding`         | `policy.open-cluster-management.io/v1`       | Top-level `placementRef`/`subjects` (not under `spec`) |
| `Policy`                   | `policy.open-cluster-management.io/v1`       | Standard policy API                                    |
| `ConfigurationPolicy`      | `policy.open-cluster-management.io/v1`       | Requires template escaping annotations                 |




## Cluster Targeting

The Placement selects managed clusters with both labels:

- `vendor=OpenShift` (set automatically by ACM)
- `cnv` (any value, checked via `Exists` operator)

Label a managed cluster for targeting:

```bash
oc label managedcluster <cluster-name> cnv=true
```

The placement intentionally does **not** use `claimSelector` for platform because BareMetal clusters report `platform=BareMetal`, not `platform=OpenShift`.

## Deployment



### Step 1: Create the Policy Namespace

```bash
oc create namespace open-cluster-management-policies 2>/dev/null || true
```



### Step 2: Deploy Placement and Binding

```bash
oc apply -f acm/placement-rule.yaml
```

This creates:

1. `ManagedClusterSetBinding` -- grants the policy namespace access to the `default` cluster set
2. `Placement` -- selects clusters with `vendor=OpenShift` + `cnv` label
3. `PlacementBinding` -- binds the placement to the BSOD policy



### Step 3: Label Target Clusters

Label each CNV-enabled managed cluster **before** deploying the policy (so ACM can immediately determine which clusters to target):

```bash
oc label managedcluster cluster-1 cnv=true
oc label managedcluster cluster-2 cnv=true
```



### Step 4: Deploy the Policy

```bash
oc apply -f acm/bsod-risk-policy.yaml
```

The policy ships with `remediationAction: inform`. On apply, ACM **reports** which
managed clusters are missing the objects but does not create them. This is
deliberate: the storage-latency thresholds are not yet empirically calibrated
against a real Windows workload (see `shared/storage-latency-thresholds.json`,
`_calibration_status`), and enforcing fleet-wide on first apply would push
uncalibrated alerting to every cluster simultaneously.

**Recommended rollout:**

1. Apply as `inform` and read the compliance report to see the blast radius.
2. Switch to `enforce` on **one** cluster (via a `PolicySet` or a placement
   override) and confirm alert volume is sane over a normal business cycle.
3. Widen to the fleet.

To enforce everywhere, set `spec.remediationAction` **and** the four
per-template `remediationAction` fields to `enforce`. ACM will then, on each
matching managed cluster:

- Create/update `PrometheusRule/bsod-risk-alerts` in `openshift-cnv`
- Create/update `PrometheusRule/bsod-risk-recording-rules` in `openshift-cnv`
- Create/update `ConfigMap/bsod-risk-grafana-dashboard` in `openshift-cnv`
- Create/update `PrometheusRule/bsod-risk-guest-alerts` in `openshift-cnv`

All four are additive, namespaced monitoring objects -- enforcing them does not
modify VMs, nodes, or cluster configuration.



### Step 5: Verify Compliance

```bash
# Check policy status on the hub
oc get policy bsod-risk-detection -n open-cluster-management-policies

# Check per-cluster compliance
oc get policy bsod-risk-detection -n open-cluster-management-policies -o jsonpath='{range .status.status[*]}{.clusterName}: {.compliant}{"\n"}{end}'
```

Expected output for a compliant cluster: `Compliant`.

## Multi-Cluster Observability (R-10)

The BSOD Detection Framework's fleet-level dashboard and cross-cluster risk aggregation require the **Multicluster Observability Operator (MCO)**. MCO federates Prometheus metrics from all managed clusters to the hub's Thanos instance, enabling a single pane of glass for BSOD risk posture across the entire fleet.

> **IMPORTANT: S3-compatible object storage is required.** MCO uses Thanos for long-term metric storage and **cannot be installed without S3-compatible object storage** (AWS S3, MinIO, OpenShift Data Foundation/Noobaa, or any S3-compatible endpoint). If your environment does not have object storage available, MCO cannot be deployed and multi-cluster metric aggregation is not possible. Per-cluster dashboards and alerts still function independently via the ACM policy above.

### Prerequisites

- ACM 2.9+ installed on the hub cluster (the BSOD policy above already requires ACM 2.16+)
- S3-compatible object storage accessible from the hub cluster
- `oc` CLI authenticated to the hub cluster with `cluster-admin`

### Step 1: Create the Observability Namespace

```bash
oc create ns open-cluster-management-observability
```

### Step 2: Copy the Global Pull Secret

MCO needs image pull access. Copy the cluster pull-secret into the observability namespace:

```bash
DOCKERCONFIGJSON=$(oc extract secret/pull-secret -n openshift-config --to=-)
oc create secret generic multiclusterhub-operator-pull-secret \
  -n open-cluster-management-observability \
  --from-literal=.dockerconfigjson="$DOCKERCONFIGJSON" \
  --type=kubernetes.io/dockerconfigjson
```

### Step 3: Create the Object Storage Secret

Create a Secret containing your S3 credentials. Choose the template matching your storage provider:

**AWS S3:**

```bash
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: thanos-object-storage
  namespace: open-cluster-management-observability
type: Opaque
stringData:
  thanos.yaml: |
    type: s3
    config:
      bucket: <BUCKET_NAME>
      endpoint: s3.<REGION>.amazonaws.com
      access_key: <ACCESS_KEY>
      secret_key: <SECRET_KEY>
EOF
```

**MinIO (on-cluster or external):**

```bash
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: thanos-object-storage
  namespace: open-cluster-management-observability
type: Opaque
stringData:
  thanos.yaml: |
    type: s3
    config:
      bucket: acm-observability
      endpoint: minio.minio.svc.cluster.local:9000
      access_key: <MINIO_ACCESS_KEY>
      secret_key: <MINIO_SECRET_KEY>
      # `insecure: true` is correct HERE and only here: this is a plain-HTTP
      # in-cluster Service address, so there is no TLS to verify. Traffic stays
      # on the pod network. This is a dev/test object store -- for production,
      # front MinIO with TLS and drop this flag.
      insecure: true
EOF
```

**OpenShift Data Foundation (ODF/Noobaa):**

```bash
# Extract credentials from Noobaa
NOOBAA_ACCESS=$(oc get secret noobaa-admin -n openshift-storage -o jsonpath='{.data.AWS_ACCESS_KEY_ID}' | base64 -d)
NOOBAA_SECRET=$(oc get secret noobaa-admin -n openshift-storage -o jsonpath='{.data.AWS_SECRET_ACCESS_KEY}' | base64 -d)
S3_ROUTE=$(oc get route s3 -n openshift-storage -o jsonpath='{.spec.host}')

cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: thanos-object-storage
  namespace: open-cluster-management-observability
type: Opaque
stringData:
  thanos.yaml: |
    type: s3
    config:
      bucket: acm-observability
      endpoint: ${S3_ROUTE}
      access_key: ${NOOBAA_ACCESS}
      secret_key: ${NOOBAA_SECRET}
      # R-34 (v0.19.0): `insecure: true` was set here and has been REMOVED.
      # Unlike the in-cluster MinIO example above, ${S3_ROUTE} is an OpenShift
      # Route -- TLS-terminated and crossing a trust boundary -- and these are
      # S3 credentials plus every cluster's metrics. Disabling certificate
      # verification on that path defeats the only protection it has.
      #
      # If Thanos cannot verify the Route's certificate, supply the CA rather
      # than switching verification off:
      #   http_config:
      #     tls_config:
      #       ca_file: /etc/tls/ca.crt
EOF
```

### Step 4: Create the MultiClusterObservability CR

```bash
cat <<'EOF' | oc apply -f -
apiVersion: observability.open-cluster-management.io/v1beta2
kind: MultiClusterObservability
metadata:
  name: observability
spec:
  observabilityAddonSpec: {}
  storageConfig:
    metricObjectStorage:
      name: thanos-object-storage
      key: thanos.yaml
    statefulSetSize: 10Gi
  advanced:
    retentionConfig:
      blockDuration: 2h
      deleteDelay: 48h
      retentionInLocal: 24h
      retentionResolutionRaw: 30d
      retentionResolution5m: 180d
      retentionResolution1h: 365d
EOF
```

### Step 5: Wait for MCO to Become Ready

```bash
oc get multiclusterobservability observability -w
```

Wait until `Ready=True` (typically 5-10 minutes). Verify all components are running:

```bash
oc get pods -n open-cluster-management-observability
```

Expected pods include: `thanos-querier`, `thanos-receive`, `thanos-compactor`, `thanos-store-shard`, `grafana`, and `observability-observatorium-api`.

### Step 6: Deploy the BSOD Custom Metrics Allowlist

```bash
oc apply -f acm/observability-metrics-custom-allowlist.yaml
```

This tells MCO which BSOD recording rules and guest metrics to forward from managed clusters to the hub. See `acm/observability-deploy-guide.md` for detailed validation queries and troubleshooting.

### Step 7: Deploy the Fleet Dashboard

```bash
oc apply -f dashboards/bsod-risk-fleet-dashboard-configmap.yaml -n openshift-config-managed
```

The fleet dashboard appears in the ACM Grafana instance under **Infrastructure > Clusters > Grafana** and visualizes cross-cluster BSOD risk scores, driver compliance, alert summaries, and top-risk VMs.

### Verification

After 5-10 minutes, verify metrics are flowing from managed clusters:

```bash
# Query hub Thanos for per-cluster risk summary
THANOS_ROUTE=$(oc get route -n open-cluster-management-observability query-frontend -o jsonpath='{.spec.host}')
# #6 (v0.16.0): this route is edge-terminated by the hub's OpenShift router,
# so its certificate is signed by the hub's INGRESS CA -- trust that bundle
# explicitly instead of `-k` skipping verification (see
# scripts/cnv-storage-latency-calibrate.sh for the same fix, verified
# against a live cluster).
INGRESS_CA=$(mktemp)
oc get configmap default-ingress-cert -n openshift-config-managed \
  -o jsonpath='{.data.ca-bundle\.crt}' > "$INGRESS_CA"
curl -s --cacert "$INGRESS_CA" \
  "https://${THANOS_ROUTE}/api/v1/query?query=bsod:cluster_risk_summary:gauge" \
  -H "Authorization: Bearer $(oc whoami -t)" | jq '.data.result'
rm -f "$INGRESS_CA"
```

Expected: one series per managed cluster with a `cluster` label.

For full validation procedures, allowlist troubleshooting, and cardinality planning, see `acm/observability-deploy-guide.md`.

## Go Template Escaping

PrometheusRule alert annotations contain Go template syntax (`{{ $labels.name }}`, `{{ $value | humanize }}`). Without protection, ACM's hub template engine attempts to interpret these as hub templates and fails.

Both annotations are required on every ConfigurationPolicy that embeds Go template syntax:

```yaml
annotations:
  policy.open-cluster-management.io/hub-templates: raw
  policy.open-cluster-management.io/disable-templates: 'true'
```

These annotations tell ACM:

- `hub-templates: raw` -- do not process embedded `{{ }}` as hub templates
- `disable-templates: true` -- completely disable template processing for this ConfigurationPolicy

If these annotations are removed, the policy fails to propagate because ACM errors on unresolvable template variables like `$labels` and `$value`.

## Regenerating from Canonical Sources

The `bsod-risk-policy.yaml` is **generated** from the canonical alert files in `alerts/` and `dashboards/`. Do not hand-edit the embedded PromQL or dashboard JSON.

When alerts or the dashboard change:

```bash
# Regenerate the ACM policy from canonical sources
python3 scripts/ci/validate-acm-policy.py --update

# Verify the policy matches canonical sources (CI parity check)
python3 scripts/ci/validate-acm-policy.py

# Apply the updated policy
oc apply -f acm/bsod-risk-policy.yaml
```



### Canonical Sources


| ConfigurationPolicy           | Source File                                     |
| ----------------------------- | ----------------------------------------------- |
| `bsod-risk-prometheusrule`    | `alerts/bsod-risk-prometheusrules.yaml`         |
| `bsod-risk-recording-rules`   | `alerts/bsod-risk-recording-rules.yaml`         |
| `bsod-risk-grafana-dashboard` | `dashboards/bsod-risk-dashboard-configmap.yaml` |
| `bsod-risk-guest-alerts`      | `alerts/bsod-risk-guest-alerts.yaml`            |




## Architecture

```
┌─────────────────────────────────────────┐
│  Hub Cluster (ACM 2.16+)                │
│  namespace: open-cluster-management-    │
│             policies                    │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │ Policy: bsod-risk-detection       │  │
│  │  ├─ ConfigPol: prometheusrule     │  │
│  │  ├─ ConfigPol: recording-rules    │  │
│  │  ├─ ConfigPol: grafana-dashboard  │  │
│  │  └─ ConfigPol: guest-alerts       │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │ Placement: bsod-risk-placement    │  │
│  │  selector: vendor=OpenShift       │  │
│  │            cnv exists             │  │
│  └───────────────────────────────────┘  │
│                   │                     │
└───────────────────┼─────────────────────┘
                    │ enforce
        ┌───────────┼───────────┐
        ▼           ▼           ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ Managed  │ │ Managed  │ │ Managed  │
│ Cluster 1│ │ Cluster 2│ │ Cluster N│
│ (cnv=t)  │ │ (cnv=t)  │ │ (cnv=t)  │
│          │ │          │ │          │
│ openshift│ │ openshift│ │ openshift│
│ -cnv/    │ │ -cnv/    │ │ -cnv/    │
│ ├ Alerts │ │ ├ Alerts │ │ ├ Alerts │
│ ├ RecRul │ │ ├ RecRul │ │ ├ RecRul │
│ ├ GstAlt │ │ ├ GstAlt │ │ ├ GstAlt │
│ └ DashCM │ │ └ DashCM │ │ └ DashCM │
└──────────┘ └──────────┘ └──────────┘
```



## What the Policy Does NOT Deploy

The ACM policy covers alerting rules, recording rules, and the dashboard ConfigMap. These components require separate deployment on each managed cluster:


| Component          | Why Not in Policy                             | Deployment Method                                     |
| ------------------ | --------------------------------------------- | ----------------------------------------------------- |
| `windows_exporter` | Guest-side install, not a Kubernetes resource | See `windows-exporter/README.md`                |
| ServiceMonitor     | Per-VM Services needed first                  | See `windows-exporter/README.md`                |
| Grafana Operator   | Heavy operator install with secrets           | See `dashboards/README.md`                      |
| BSOD audit scripts | CLI tools, not cluster state                  | Run manually via `scripts/cnv-win-bsod-audit.sh`      |
| Must-gather image  | Container image, not policy-managed           | Pull from `quay.io/jburck/pg-must-gather-bsod:v0.27.1` |
| `bsod-fleet-exporter` Deployment (Issue K / R-27) | Per-cluster Deployment + ServiceAccount + NetworkPolicy, not a template-friendly single object like a PrometheusRule; also works standalone on clusters with **no RHACM at all** | `oc apply -f exporter/` on each cluster -- see `exporter/README.md`. Its two PrometheusRule outputs (`BSODRisk_FleetEvidenceIncomplete`, `BSODRisk_ExporterCollectionFailing`) DO ship fleet-wide via this policy once deployed, same as any other alert above |
| Cluster Observability Operator UI plugins | Console-level enhancement (RHACM alert/incident view, Korrel8r correlation, Perses dashboards) built on top of the MCO deployment below, not policy-managed | See `coo/README.md`      |




## NIST SP 800-53 Mapping

The policy is annotated with NIST SP 800-53 controls:


| Annotation   | Value                       |
| ------------ | --------------------------- |
| `categories` | CM Configuration Management |
| `controls`   | CM-2 Baseline Configuration |
| `standards`  | NIST SP 800-53              |


This maps to CM-2: "The organization develops, documents, and maintains under configuration control, a current baseline configuration of the information system." The BSOD detection rules establish a monitoring baseline for Windows VM health.

## Troubleshooting


| Issue                                               | Resolution                                                                                                                                                                        |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Policy shows `NonCompliant`                         | Run `oc describe policy bsod-risk-detection -n open-cluster-management-policies` to see per-template compliance details.                                                          |
| Placement matches no clusters                       | Verify target clusters have both `vendor=OpenShift` and `cnv` labels: `oc get managedcluster --show-labels`.                                                                      |
| Alert annotations render as `{{ $labels }}` literal | ACM's hub template engine consumed the Go templates. Confirm both `hub-templates: raw` and `disable-templates: true` annotations are on the ConfigurationPolicy.                  |
| Policy not propagating                              | Verify the `ManagedClusterSetBinding` exists and references the correct cluster set: `oc get managedclustersetbinding -n open-cluster-management-policies`.                       |
| `validate-acm-policy.py` fails                      | Policy is out of sync with canonical sources. Run `python3 scripts/ci/validate-acm-policy.py --update` to regenerate.                                                             |
| Dashboard ConfigMap not visible in console          | The ConfigMap is deployed to `openshift-cnv` (not `openshift-config-managed`). For OCP console discovery, the ConfigMap needs the `console.openshift.io/dashboard: "true"` label. |
| Guest alerts show no data after policy applies      | `windows_exporter` must be deployed inside Windows VMs separately -- the policy only creates the PrometheusRule CR. See `windows-exporter/README.md`.                       |
| Recording rules not producing data                  | VMs must be running with active I/O for `kubevirt_vmi_storage_*` counters to increment. The 24h recording rule needs 24h of accumulated data.                                     |
| ACM version < 2.16                                  | The `ManagedClusterSetBinding` uses `v1beta2` API. On ACM < 2.16, change to `v1beta1` or remove the binding and use a different cluster set approach.                             |

## Reference Links

RHACM Support Policy Matrix Documentaiton

- [RHACM Lifecycle & Update Policies](https://access.redhat.com/support/policy/updates/advanced-cluster-management)
  - Missing from document above
    - [Red Hat Advanced Cluster Management for Kubernetes 2.16 Support Matrix](https://access.redhat.com/articles/7136928)
    - [Red Hat Advanced Cluster Management for Kubernetes 2.17 Support Matrix](https://access.redhat.com/articles/7142376)
