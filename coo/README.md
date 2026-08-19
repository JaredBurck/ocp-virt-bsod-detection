# Cluster Observability Operator (COO) Integration Guide for BSOD Detection

## Overview

The Cluster Observability Operator (COO) is an **optional** Red Hat OpenShift Operator -- optional in exactly the same sense as [RHACM](../acm/README.md) and [`windows_exporter`](../windows-exporter/README.md) are optional in this framework. Nothing in `alerts/`, `dashboards/`, or `scripts/` depends on COO. It is documented here because it adds console-native capabilities that are directly useful for BSOD triage without requiring the Grafana Operator stack (`dashboards/grafana-5.24.0.yaml`) or a second must-gather/analyzer pass.

**COO has two genuinely independent halves relevant to this framework, and only one of them has anything to do with RHACM:**

| | Applies to | Requires RHACM? |
|---|---|:---:|
| **[Part A -- Single-Cluster](#part-a-single-cluster-capabilities-no-rhacm-required)** | Any individual OCP Virt cluster running the `alerts/` `BSODRisk_*` `PrometheusRule` CRs | **No** |
| **[Part B -- Multi-Cluster / RHACM](#part-b-multi-cluster-rhacm-integration)** | The RHACM **hub** cluster, on top of the MCO deployment in `acm/observability-deploy-guide.md` | **Yes** |

If you do not run RHACM, Part A is the entire relevant scope of this document -- skip Part B entirely. If you do run RHACM, Part B is additive on top of Part A; it does not replace it, and it must be deployed on the hub, not on managed clusters.

COO does **not** replace the Cluster Monitoring Operator (CMO), the platform Prometheus/Alertmanager stack the `BSODRisk_*` `PrometheusRule` CRs in `alerts/` already depend on, or the ACM governance policy in `acm/`. It runs alongside all of them.

> **Confidence tier for this document:** All version numbers, CRD schemas, and YAML examples below are sourced directly from Red Hat's official COO documentation and RHSA/RHBA errata (cited in [Reference Links](#reference-links)) -- treat those as [KCS-VALIDATED]-equivalent for the *product facts*. The specific *integration recipes* connecting COO to this framework's existing alerts/dashboards/ACM artifacts (Parts A and B below) are **[UNVALIDATED]** -- they have not been exercised against a live cluster the way the Grafana Operator (`dashboards/README.md`) and MCO (`acm/observability-deploy-guide.md`) procedures have. Treat the YAML in this directory as a validated starting point, not a drop-in production artifact.

## Current Version

**COO 1.5.1** is current as of this writing (2026-08-02; shipped as a z-stream bug-fix release shortly after 1.5.0, per RHSA-2026:26010 and RHSA-2026:34342). COO 1.5's headline feature is **general availability of the Red Hat build of Perses** and **general availability of the `MonitoringStack` CRD** (previously Technology Preview -- tracked upstream as `COO-1742`). Everything in this guide targets 1.5.x; where a capability requires a different minimum COO or OCP version, it is called out explicitly in [Version Dependency Matrix](#version-dependency-matrix).

COO is **not** the same project as the community `grafana-operator` used in `dashboards/grafana-5.24.0.yaml` (OperatorHub `grafana-operator`, upstream `integreatly-org/grafana-operator`). They are independent operators that can coexist; see [How This Fits With the Rest of the Framework](#how-this-fits-with-the-rest-of-the-framework) for when to prefer one over the other.

## How This Fits With the Rest of the Framework

```
Layer 3: PrometheusRule Alerts (alerts/)
  BSODRisk_* alerts, evaluated by platform Prometheus (CMO-managed)
  in openshift-cnv/openshift-monitoring -- UNCHANGED by anything below
                    |
                    | (every cluster, RHACM or not)
                    v
  +---------------------------------------------------------------+
  |  PART A -- single-cluster, no RHACM required                  |
  |                                                                |
  |  Grafana Operator          Cluster Observability Operator     |
  |  (dashboards/, optional)   (coo/, this dir, optional)         |
  |  full Grafana +            - TroubleshootingPanel (Korrel8r)  |
  |  oauth-proxy renders         signal correlation for a firing  |
  |  bsod-risk-*.json            BSODRisk_* alert                 |
  |                             - Perses dashboards: alt. to the  |
  |                               Grafana Operator, same JSON     |
  +---------------------------------------------------------------+
                    |
                    | (only if RHACM is also deployed)
                    v
  +---------------------------------------------------------------+
  |  PART B -- hub cluster only, requires RHACM + MCO              |
  |                                                                |
  |  ACM Policy (acm/)  -->  MCO (acm/observability-deploy-guide.md)
  |  distributes alerts/    Thanos federation on the hub          |
  |  fleet-wide                       |                           |
  |                                   v                           |
  |                     COO Monitoring UIPlugin (coo/, this dir)  |
  |                     RHACM alert view + incident detection,    |
  |                     reads FROM the MCO endpoints above         |
  +---------------------------------------------------------------+
```

The important relationship to understand for Part B: **COO's RHACM alert integration is built on top of the MCO deployment already documented in `acm/README.md`'s "Multi-Cluster Observability (R-10)" section, not a replacement for it.** The `UIPlugin`'s `spec.monitoring.acm.alertmanager.url` and `thanosQuerier.url` point at the exact `open-cluster-management-observability` namespace Services that `acm/observability-deploy-guide.md` Steps 1-5 already stand up. If you have not deployed MCO, [Part B](#part-b-multi-cluster-rhacm-integration) has nothing to talk to.

## Prerequisites

Before deploying anything in this directory, confirm:

- OpenShift Container Platform 4.15+ (4.19+ if you want the troubleshooting panel -- see the version matrix below)
- `cluster-admin` access (`oc whoami`)
- `community-operators`/`redhat-operators` `CatalogSource` available: `oc get catalogsource -n openshift-marketplace`
- COO installed (see [Installation](#installation) below) -- required for both Part A and Part B
- **Part A only:** `dashboards/bsod-risk-overview.json` (used as the Perses migration source, if using [A2](#a2-perses-dashboards-grafana-operator-alternative))
- **Part B only:** MCO already deployed on the hub per `acm/observability-deploy-guide.md` (Steps 1-5)

## Version Dependency Matrix

COO's feature availability is gated by **both** the COO version and the OCP version -- a newer COO does not unlock a feature on an older OCP release. This table is reproduced from Red Hat's official COO release notes (see [Reference Links](#reference-links)):

| COO Version | OCP Version | Distributed Tracing | Logging | Troubleshooting Panel (Part A) | RHACM Alerts (Part B) | Incident Detection (Part B) |
|---|---|:---:|:---:|:---:|:---:|:---:|
| 1.1+ | 4.12 - 4.14 | Yes | Yes | No | No | No |
| 1.1+ | 4.15 | Yes | Yes | No | Yes | No |
| 1.1+ | 4.16 - 4.18 | Yes | Yes | No | Yes | No |
| 1.2+ | 4.19+ | Yes | Yes | Yes | Yes | Yes |

Additional version-specific gates relevant to this framework:

| Feature | Part | Minimum COO | Minimum OCP | Notes |
|---|---|---|---|---|
| `MonitoringStack` CRD as GA (not Technology Preview) | A | 1.5.0 | 4.12+ | Was Technology Preview through COO 1.4 (`COO-1742`) |
| Red Hat build of Perses (GA) | A | 1.5.0 | 4.15+ | Technology Preview in COO 1.4; requires the `monitoring` UIPlugin with `spec.monitoring.perses.enabled: true` |
| Perses dashboards reconciling correctly after a 1.2 upgrade | A | 1.5.1 | -- | An old version label matcher left over from the COO 1.2 upgrade could leave Perses dashboards unavailable; fixed in 1.5.1 |
| Troubleshooting panel does not include RHACM's `managed_cluster` label in Korrel8r queries (only relevant if RHACM/Part B is *also* installed on the same cluster) | A | 1.4+ | -- | Earlier versions send `managed_cluster` to Korrel8r, which cannot resolve it, so the correlation graph silently renders empty |
| RHACM alert integration surviving operator upgrades | B | 1.2.2+ | -- | COO 1.2.0 -> 1.2.1 upgrades could silently empty the `UIPlugin` spec, losing RHACM/Perses/incident config (fixed 1.2.2; re-broken and re-fixed once more before 1.5, per COO-1051/COO-1062) -- if you are running an older COO and the `UIPlugin` shows only `type:` with no nested config after an upgrade, recreate it |
| `clusterHealthAnalyzer.enabled` (incident detection) replaces `incidents.enabled` | B | 1.4+ | 4.19+ | `incidents.enabled` still works during the deprecation window; new deployments should use `clusterHealthAnalyzer` |

**Practical implication for this framework:** on OCP 4.16-4.18 you get Part B (RHACM alert visibility) if you run RHACM, but not the Part A troubleshooting panel -- that needs 4.19+ regardless of RHACM. Perses (also Part A) needs COO 1.5+ and OCP 4.15+ regardless of how new your OCP is or whether RHACM is present.

## Installation

### Step 1: Subscribe to the Operator

```bash
oc apply -f coo/subscription.yaml
```

This creates the `openshift-cluster-observability-operator` namespace, an `OperatorGroup`, and a `Subscription` on the `stable` channel. COO installs and manages the Perses Operator and its CRDs (`PersesDashboard`, `PersesDatasource`, `PersesGlobalDatasource`) automatically -- no separate Perses subscription is needed. This step is identical whether you only need Part A or also plan to deploy Part B.

Enable cluster monitoring integration for the operator's own namespace (required for Part B's incident detection to receive alert data; harmless if you only use Part A):

```bash
oc label namespace openshift-cluster-observability-operator openshift.io/cluster-monitoring=true
```

### Step 2: Verify

```bash
oc get csv -n openshift-cluster-observability-operator
oc get pods -n openshift-cluster-observability-operator
# Expect a cluster-observability-operator pod and a perses-operator pod, both Running
```

---

## Part A: Single-Cluster Capabilities (No RHACM Required)

Everything in this section runs on the same OCP Virt cluster that already hosts the `BSODRisk_*` `PrometheusRule` CRs from `alerts/`. None of it requires RHACM, MCO, or a hub/managed-cluster topology.

### A1. Troubleshooting Panel (Korrel8r Signal Correlation)

**Requires OCP 4.19+ for general availability** (Technology Preview on 4.17-4.18 per community reporting; not available before 4.17). See the version matrix above.

```bash
oc apply -f coo/uiplugin-troubleshooting-panel.yaml
```

**Why this is useful for BSOD triage:** the panel is available from **Observe > Alerting**, and from a firing `BSODRisk_*` alert it produces an interactive node graph correlating the alert to the underlying VMI, the `virt-launcher` pod, the node, and (if `cluster-logging`/LokiStack is deployed) related log lines -- the same kind of correlation a TSE currently does by hand in Layer 4/must-gather analysis (R-8b in `docs/design/roadmap-v1.0.md`, retired), but available at alert time without waiting for a must-gather. This does not replace `analyze.py`'s vendor-routing and KCS-linked findings; it is a faster first look while deciding whether to escalate.

If RHACM/Part B is *also* installed on this same cluster, confirm you are on COO 1.4+ -- earlier versions include RHACM's `managed_cluster` external label in the Korrel8r query, which Korrel8r cannot resolve, silently leaving the correlation graph empty (no error is shown). This does not apply if you only use Part A.

### A2. Perses Dashboards (Grafana Operator Alternative)

**Requires COO 1.5+ and OCP 4.15+.** This is an *alternative* deployment path to `dashboards/README.md` Method 1 (Grafana Operator), not a required upgrade -- both can coexist, and the canonical dashboard source of truth remains `dashboards/bsod-risk-overview.json` either way.

#### Step 1: Enable Perses

```yaml
apiVersion: observability.openshift.io/v1alpha1
kind: UIPlugin
metadata:
  name: monitoring
spec:
  type: Monitoring
  monitoring:
    perses:
      enabled: true
```

This minimal manifest is shipped as `coo/uiplugin-monitoring-perses-only.yaml` -- apply it directly:

```bash
oc apply -f coo/uiplugin-monitoring-perses-only.yaml
```

If you also plan to deploy Part B on this cluster (i.e., this is the RHACM hub), use the combined `coo/uiplugin-monitoring.yaml` instead, which sets `perses.enabled: true` alongside the RHACM/incident-detection fields -- see [B1](#b1-rhacm-alert-and-incident-detection-ui-plugin). Applying `clusterHealthAnalyzer`/`acm` fields on an OCP release below the 4.19 minimum (see the version matrix above) or without MCO deployed has not been validated -- use the Perses-only manifest on any cluster that is not an RHACM hub, even if it otherwise meets the COO/OCP version floor.

#### Step 2: Create the Global Thanos Querier Datasource

`coo/perses-thanos-global-datasource.yaml` requires a Kubernetes Secret named `thanos-querier-datasource-secret` to already exist in the COO operator namespace (`openshift-cluster-observability-operator`) *before* it is applied -- Red Hat's own COO documentation states this prerequisite but does not show the literal creation command. Live-cluster validated (2026-08-02, COO 1.5.1) recipe, following the same SA-bearer-token pattern `dashboards/README.md` Step 3 uses for Grafana:

```bash
# ServiceAccount + cluster-monitoring-view binding (read access to platform Thanos Querier)
oc create serviceaccount perses-thanos-sa -n openshift-cluster-observability-operator
oc adm policy add-cluster-role-to-user cluster-monitoring-view \
  -z perses-thanos-sa -n openshift-cluster-observability-operator

# Bearer-token Secret -- key MUST be named "Authorization" (full "Bearer <token>" string,
# not just the raw JWT) -- this is the Perses operator's HTTPProxy secret convention,
# distinct from Grafana's httpHeaderValue1 jsonData/secureJsonData split in dashboards/README.md.
TOKEN=$(oc create token perses-thanos-sa -n openshift-cluster-observability-operator --duration=8760h)
oc create secret generic thanos-querier-datasource-secret \
  -n openshift-cluster-observability-operator \
  --from-literal=Authorization="Bearer ${TOKEN}"
```

Then apply the datasource:

```bash
oc apply -f coo/perses-thanos-global-datasource.yaml
```

**What actually happens under the hood:** the Perses Operator reads this native k8s Secret and uses it to populate an *internal* Perses `GlobalSecret` object named `<PersesGlobalDatasource-name>-secret` (e.g. `bsod-thanos-querier-datasource-secret` for the CR name used below) -- a different name than the k8s Secret you created. This is expected; do not be alarmed if `oc logs -n openshift-cluster-observability-operator perses-0` shows a `GET`/`PUT` against that different, auto-derived name. Verify success via the CR's own status instead of the internal name:

```bash
oc get persesglobaldatasources bsod-thanos-querier-datasource \
  -o jsonpath='{.status.conditions}'
# Expect: {"type":"Available","status":"True", ...}
```

This points Perses at the **same** platform `thanos-querier.openshift-monitoring.svc.cluster.local:9091` endpoint that `dashboards/grafana-5.24.0.yaml`'s Grafana datasource uses (see `dashboards/README.md` Step 4) -- the same `BSODRisk_*` alert data, recording rules, and `windows_exporter` metrics are available either way. It reuses the cluster's own service CA (`openshift-service-ca.crt`) for TLS trust, matching the `dashboards/README.md`/`windows-exporter/README.md` convention of trusting the in-cluster CA explicitly rather than skipping verification.

#### Step 3: Import the BSOD Dashboard

Two options, neither of which is scripted into this repo's `scripts/generate-dashboard-artifacts.sh` pipeline (that pipeline only produces Grafana-consumable artifacts; a Perses import is a one-time, cluster-side action against the same JSON, not a build artifact this repo ships pre-converted):

**Option A -- web console:** In the OpenShift console, navigate to **Observe > Dashboards (Perses)**, use the Grafana import feature, and paste in the contents of `dashboards/bsod-risk-overview.json`.

**Option B -- CLI (`percli`):**

```bash
percli migrate -f dashboards/bsod-risk-overview.json --online -o yaml > bsod-risk-overview-perses.yaml
oc apply -f bsod-risk-overview-perses.yaml
```

The `--online` flag contacts the Perses server for the current plug-in translation logic; do not commit the generated YAML back into `dashboards/` -- that directory's "source of truth" convention (`dashboards/README.md`'s "Keeping JSON and YAML in Sync") applies only to the Grafana-consumable artifacts `generate-dashboard-artifacts.sh` produces.

**Option C -- `percli`-free, using the Perses server's own `/api/migrate` endpoint directly (live-cluster validated 2026-08-02, no `percli` binary required):**

`percli migrate --online` is a thin client around `POST /api/migrate` on the Perses server itself -- that endpoint requires no authentication (only dashboard *storage* endpoints do) and is reachable from inside the cluster network, so it can be driven with plain `curl`/`oc port-forward` when `percli` is not installed locally:

```bash
# Port-forward to the in-cluster Perses service (TLS on 8080; -k because it presents
# the cluster's own service-serving cert, which curl on your workstation doesn't trust)
oc port-forward -n openshift-cluster-observability-operator svc/perses 18080:8080 &

# Wrap the Grafana JSON per the /api/migrate request contract and translate
python3 -c "
import json
gd = json.load(open('dashboards/bsod-risk-overview.json'))
json.dump({'grafanaDashboard': gd}, open('/tmp/migrate-request.json', 'w'))
"
curl -sk -X POST https://localhost:18080/api/migrate \
  -H "Content-Type: application/json" \
  -d @/tmp/migrate-request.json > /tmp/migrated-dashboard.json
```

**Two migration bugs to patch before applying** -- see "Confirmed migration bugs" below for the full detail; both were hit migrating this exact dashboard:

```bash
python3 -c "
import json, yaml

d = json.load(open('/tmp/migrated-dashboard.json'))

def fix_queries(obj):
    if isinstance(obj, dict):
        if obj.get('kind') == 'LogQuery' and obj.get('spec', {}).get('plugin', {}).get('kind') == 'LokiLogQuery':
            obj['kind'] = 'TimeSeriesQuery'
            obj['spec']['plugin']['kind'] = 'PrometheusTimeSeriesQuery'
        for v in obj.values():
            fix_queries(v)
    elif isinstance(obj, list):
        for item in obj:
            fix_queries(item)

def fix_colors(obj):
    if isinstance(obj, dict):
        if obj.get('color') == 'text':
            obj['color'] = '#808184'
        for v in obj.values():
            fix_colors(v)
    elif isinstance(obj, list):
        for item in obj:
            fix_colors(item)

fix_queries(d['spec'])
fix_colors(d['spec'])

# Wrap in a PersesDashboard CR (namespace = the Perses 'project' it lands in --
# see 'Namespace and project mapping' above; the Global Thanos datasource from
# Step 2 above resolves from any namespace)
cr = {
  'apiVersion': 'perses.dev/v1alpha2',
  'kind': 'PersesDashboard',
  'metadata': {'name': 'bsod-risk-overview', 'namespace': 'openshift-cluster-observability-operator'},
  'spec': {'config': d['spec']},
}
yaml.dump(cr, open('/tmp/persesdashboard-cr.yaml', 'w'), default_flow_style=False, sort_keys=False)
"
oc apply -f /tmp/persesdashboard-cr.yaml
oc get persesdashboard bsod-risk-overview -n openshift-cluster-observability-operator -o jsonpath='{.status.conditions}'
# Expect: {"type":"Available","status":"True", ...}
```

Do not commit `/tmp/migrated-dashboard.json` or `/tmp/persesdashboard-cr.yaml` back into `dashboards/` or `coo/` -- same source-of-truth rule as Option B.

**Known migration limitations** (from Red Hat's official migration guidance -- verify against the actual converted dashboard before relying on it):

| Grafana Feature | Perses Migration Behavior |
|---|---|
| Custom/community Grafana panel plugins | Not supported; must be replaced with a built-in Perses panel type |
| Grafana-native alerting | Not migrated -- the BSOD alerts already exist as `PrometheusRule` CRs in `alerts/`, independent of any dashboard tool, so this has no practical impact here |
| Template variables (e.g., the dashboard's VM-name variable) | Syntax differences may require manual adjustment post-migration -- verify the VM dropdown still populates correctly |
| Advanced/niche panel types | May require conversion to a supported Perses plugin kind |

**Confirmed migration bugs (live-cluster validated, 2026-08-02, `percli`-equivalent `/api/migrate` call against `bsod-risk-overview.json` on COO 1.5.1):**

- **Prometheus queries mis-typed as `LogQuery`/`LokiLogQuery`:** 13 of `bsod-risk-overview.json`'s 16 panels had every Prometheus query plugin rewritten to `kind: LogQuery` / `spec.plugin.kind: LokiLogQuery` instead of `kind: TimeSeriesQuery` / `spec.plugin.kind: PrometheusTimeSeriesQuery`. The PromQL expression string itself survives intact in `spec.plugin.spec.query` -- only the query *kind* is wrong -- so this is a mechanical, scriptable fix, not data loss. A `PersesDashboard`/`PersesGlobalDashboard` created from the unpatched migration output still reconciles as `Available: True` (the malformed query kind is not a schema violation, just wrong at query time), so this does **not** surface as an error the way the color bug below does -- verify panel data actually renders, don't rely on `Available: True` alone.
- **Grafana's `"text"` threshold color literal fails Perses' hex-only validation:** Grafana's special "use theme text color" keyword (`"color": "text"`, used here for the 0/no-data step of the `bsod:cluster_cpu_model_count:gauge` `StatChart` panel's value mappings and thresholds) has no Perses equivalent and is carried over verbatim by the migration tool. Perses' CUE schema requires `^#(?:[0-9a-fA-F]{3}){1,2}$`, so **this one does hard-fail**: applying an unpatched `PersesDashboard` CR containing it sets `Available: False` / `Degraded: True` with a `PersesBackendError` citing `spec.mappings.0.kind: conflicting values ... StatusCode: 400`. Replace `"text"` with a real hex value (e.g. a neutral gray) before applying.

Both were fixed with a single idempotent Python pass (walk `spec.panels`, rewrite `kind`/`plugin.kind` pairs, replace the `"text"` color literal) run once against the migration output before wrapping it in a `PersesDashboard` CR -- there is no `percli`/COO flag that avoids either bug. Re-run this check after any future edit to `dashboards/bsod-risk-overview.json` and before committing a Perses-side artifact for it.

### A3. MonitoringStack: Why It Is Not Recommended for BSOD Alerts (Yet)

COO 1.5.0 made the `MonitoringStack` CRD generally available -- a standalone, independently configured Prometheus + Alertmanager + Thanos Querier stack, separate from the platform monitoring stack the Cluster Monitoring Operator (CMO) manages. It is also single-cluster/no-RHACM, documented here for completeness because it is COO's flagship capability, but **[UNVALIDATED]** for this specific use: the `BSODRisk_*` alerts and recording rules in `alerts/` are designed to run against the **platform** Prometheus instance in `openshift-monitoring`/`openshift-cnv` (the one CMO already manages and that scrapes `kubevirt_vmi_*` metrics and `windows_exporter` Services by default via the standard OCP Virt monitoring integration). Running them on a separate `MonitoringStack` instance instead would require:

- Re-declaring `ServiceMonitor`/`PodMonitor` discovery for `virt-launcher` pods and every per-VM `windows_exporter` Service the `MonitoringStack`'s `resourceSelector`/`namespaceSelector` would need to find (duplicating, not replacing, what CMO's default KubeVirt integration already scrapes)
- Re-pointing the `alerts/` `PrometheusRule` CRs, the ACM policy's embedded copies, and every `promtool`/Prometheus-exec verification command in `alerts/README.md`, `windows-exporter/README.md`, and `docs/operator-runbook.md` at the new stack's API endpoint instead of `prometheus-k8s-0`/`thanos-querier.openshift-monitoring.svc`

None of that has been exercised end-to-end against a live cluster. If you have a specific multi-tenancy reason to isolate BSOD alerting into its own `MonitoringStack` (e.g., a shared cluster where BSOD alerting must not consume the platform Alertmanager's routing config), treat it as a research spike, not a supported deployment path, and validate every cross-reference above before trusting the result.

---

## Part B: Multi-Cluster / RHACM Integration

Everything in this section requires RHACM, and is deployed on the **hub** cluster only (never on managed clusters). Skip this entire section if you do not run RHACM -- Part A above is complete and self-sufficient without it.

### B1. RHACM Alert and Incident Detection UI Plugin

**Prerequisite:** MCO deployed on the hub per `acm/observability-deploy-guide.md`. This UIPlugin is deployed **on the hub cluster** (where RHACM + MCO already run), not on managed clusters.

```bash
oc apply -f coo/uiplugin-monitoring.yaml
```

`coo/uiplugin-monitoring.yaml` deploys the `Monitoring` UIPlugin with `spec.monitoring.acm.enabled: true` pointed at the same `alertmanager.open-cluster-management-observability.svc:9095` and `rbac-query-proxy.open-cluster-management-observability.svc:8443` endpoints that `acm/observability-deploy-guide.md` Step 4 (`MultiClusterObservability` CR) already stands up, plus `clusterHealthAnalyzer.enabled: true` for incident detection. It also sets `perses.enabled: true`, so if the hub cluster itself needs [A2](#a2-perses-dashboards-grafana-operator-alternative), this single manifest covers both Part A and Part B for that cluster.

**What this adds on top of `acm/`:** the ACM policy in `acm/bsod-risk-policy.yaml` distributes the `PrometheusRule` CRs and dashboard ConfigMap to managed clusters; MCO federates their metrics to the hub's Thanos. This UIPlugin is the piece that lets a hub-cluster console user browse `BSODRisk_*` alerts fired on any managed cluster -- and see them grouped into incidents when a wave of alerts fires together (e.g., a storage-latency burst that trips `BSODRisk_StorageLatencyElevated`, `BSODRisk_StorageLatencyHigh`, and `BSODRisk_StorageLatencyBurst` on several VMs in the same 5-minute window) -- without leaving the OpenShift console or standing up a separate Grafana instance.

**Verify:**

```bash
oc get uiplugin monitoring -o jsonpath='{.status.conditions}'
```

In the console: **Observe > Alerting > Incidents** tab. Allow at least 5 minutes after enabling for the first correlation pass; only alerts firing *after* enablement are included (previously-resolved alerts are not backfilled into incident history).

---

## What COO Does NOT Provide for This Framework

Mirroring `acm/README.md`'s "What the Policy Does NOT Deploy" table:

| Component | Why COO Doesn't Cover It | Where It's Actually Handled |
|---|---|---|
| `BSODRisk_*` `PrometheusRule` evaluation | COO's UI plugins are consumers of alert data, not an alerting engine | `alerts/` (platform Prometheus, CMO-managed) |
| Fleet-wide policy distribution/drift correction | COO has no multi-cluster governance concept | `acm/bsod-risk-policy.yaml` (ACM ConfigurationPolicy) |
| Cross-cluster metric federation | COO's RHACM UIPlugin (Part B) *reads from* MCO's federated Thanos; it does not federate anything itself | MCO, `acm/observability-deploy-guide.md` |
| `windows_exporter` guest metrics | Guest-side install, not a Kubernetes/console resource | `windows-exporter/README.md` |
| BSOD gate scripts / `analyze.py` | CLI/offline tools, not cluster state or a console feature | `scripts/cnv-win-bsod-audit.sh`, `insights-rules/analyze.py` |
| Must-gather crash/QMP log analysis | COO's troubleshooting panel (Part A) correlates *live* signals; it does not parse historical must-gather archives | `insights-rules/plugins/bsod_crashdump_checks.py` |

## Troubleshooting

| Issue | Part | Resolution |
|---|---|---|
| `UIPlugin` shows `type: Monitoring` with no nested `monitoring:` config after an operator upgrade | A/B | Known regression class across several COO versions (COO-1051, COO-1062, and the general "config lost on upgrade" issue fixed in 1.2.2 but recurring pre-1.5). Recreate the `UIPlugin` from `coo/uiplugin-monitoring.yaml` |
| Perses dashboards show unavailable/no pods after upgrading from COO 1.2.x | A | Old version label matcher left over from the 1.2 upgrade; fixed in 1.5.1. Upgrade to 1.5.1+ |
| Troubleshooting panel correlation graph is empty on an RHACM-enabled cluster | A | Requires COO 1.4+ (removes the unresolvable `managed_cluster` label from Korrel8r queries) |
| Incident detection tab shows no data | B | Confirm the operator namespace has `openshift.io/cluster-monitoring=true` (Installation Step 1 above) and wait at least 5 minutes -- status updates are recorded on a 5-minute cadence, and only alerts firing after enablement are counted |
| `Observe > Dashboards (Perses)` menu never appears | A | Confirm OCP 4.15+ and COO 1.5+ (see version matrix). Allow a few minutes after applying the `UIPlugin`; also verify `oc get crds \| grep perses` returns `persesdashboards.perses.dev`, `persesdatasources.perses.dev`, `persesglobaldatasources.perses.dev` |
| Perses dashboard panels empty after a `percli migrate` import | A | Confirm the `PersesGlobalDatasource` (`coo/perses-thanos-global-datasource.yaml`) applied successfully (`oc get persesglobaldatasources`) and that its `spec.config.default: true` datasource resolves before any namespace-scoped `PersesDatasource` you may also have |
| RHACM alert data never appears in the Monitoring UIPlugin | B | Confirm MCO is deployed and `Ready` per `acm/observability-deploy-guide.md`, and that the `alertmanager`/`thanosQuerier` URLs in `coo/uiplugin-monitoring.yaml` match your actual `open-cluster-management-observability` namespace endpoints |
| `no matches for kind "UIPlugin"` on first apply | A/B | OLM has not finished registering COO's CRDs yet. Wait ~1-2 minutes after the `Subscription` reaches `AtLatestKnown` and re-apply |

## Reference Links

- [Cluster Observability Operator release notes (1-latest)](https://docs.redhat.com/en/documentation/red_hat_openshift_cluster_observability_operator/1-latest/observability/red_hat_openshift_cluster_observability_operator_release_notes/index) -- version history, COO-version-to-OCP-version feature matrix, per-release bug fixes
- [Installing the Cluster Observability Operator](https://docs.redhat.com/en/documentation/red_hat_openshift_cluster_observability_operator/1-latest/observability/installing_red_hat_openshift_cluster_observability_operator/coo-installing-object-storage-types_installing-end-to-end-observability) -- OperatorHub/OLM installation procedure
- [Monitoring UI plugin (RHACM + incident detection)](https://docs.redhat.com/en/documentation/red_hat_openshift_cluster_observability_operator/1-latest/html/ui_plugins_for_red_hat_openshift_cluster_observability_operator/monitoring-ui-plugin) -- `UIPlugin` schema, incident detection behavior (Part B)
- [Observability UI plugins overview](https://docs.redhat.com/en/documentation/red_hat_openshift_cluster_observability_operator/1-latest/html/ui_plugins_for_red_hat_openshift_cluster_observability_operator/observability-ui-plugins-overview) -- Troubleshooting panel (Korrel8r), Logging, Distributed Tracing plugin summaries (Part A)
- [Perses dashboards chapter](https://docs.redhat.com/en/documentation/red_hat_openshift_cluster_observability_operator/1-latest/html/ui_plugins_for_red_hat_openshift_cluster_observability_operator/perses-dashboard) -- `PersesDashboard`/`PersesDatasource`/`PersesGlobalDatasource` CRs, Grafana migration steps (Part A)
- [Monitoring API reference (`MonitoringStack`, `ThanosQuerier`)](https://docs.redhat.com/en/documentation/red_hat_openshift_cluster_observability_operator/1-latest/html/api_reference_for_red_hat_openshift_cluster_observability_operator/api-monitoring-package) (Part A)
- [RHSA-2026:26010 -- Cluster Observability Operator 1.5.0](https://access.redhat.com/errata/RHSA-2026:26010)
- [RHSA-2026:34342 -- Cluster Observability Operator 1.5.0](https://access.redhat.com/errata/RHSA-2026:34342)
- [Visualize your cluster: Manage observability with Red Hat build of Perses (Red Hat Developer, 2026-07-07)](https://developers.redhat.com/articles/2026/07/07/manage-observability-red-hat-build-perses)
- [Red Hat build of Perses with the cluster observability operator (Red Hat Developer, 2026-04-02)](https://developers.redhat.com/articles/2026/04/02/red-hat-build-perses-cluster-observability-operator)
- [New observability features in Red Hat OpenShift 4.22](https://www.redhat.com/en/blog/new-observability-features-red-hat-openshift-422) -- COO 1.5 feature announcement (Perses GA)
