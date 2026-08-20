# BSOD Fleet Evidence-Completeness Exporter

Continuous export of per-VM evidence completeness (Issue K / R-27).
See `scripts/cnv-bsod-fleet-exporter.sh`'s module header and this README
for deploy steps, metrics, and interval-vs-fleet-size guidance.

Loops `cnv-win-bsod-audit.sh --json` on an interval and serves the per-VM
evidence-completeness data it already computes as Prometheus gauges. Read-only
-- never mutates a VM, node, or any other cluster object.

## What "evidence completeness" means

Of the checks the BSOD audit tries to run on a given VM, the percentage that
actually reached a verdict (FAIL/WARN/PASS) rather than UNKNOWN. A VM with no
QEMU Guest Agent and no `windows_exporter` deployed will score low even if it
has zero BSOD risk findings -- low evidence completeness means "we might be
blind here", not "there is risk here". See
`shared/evidence-completeness-thresholds.json` for the fleet-wide alert
threshold and its rationale.

## Deploy

**`exporter/networkpolicy.yaml` is REQUIRED, not optional.** `/metrics` has no
authentication of its own (see "Metrics emitted" below) -- the NetworkPolicy
is the *only* access control between "an operator scrapes this from
Prometheus" and "any pod in any namespace on the cluster reads fleet-wide
VM/namespace inventory over the Service's ClusterIP." Do not skip this step,
and do not treat `oc apply` succeeding as proof it is enforced -- see the
verification command below.

```bash
oc apply -f tekton/rbac.yaml          # provides the bsod-audit-gate ClusterRole this exporter's SA binds to
oc apply -f exporter/service-account.yaml
oc apply -f exporter/deployment.yaml
oc apply -f exporter/service.yaml
oc apply -f exporter/servicemonitor.yaml
oc apply -f exporter/networkpolicy.yaml            # REQUIRED -- see above. Requires a NetworkPolicy-enforcing CNI (OVN-Kubernetes, OCP 4.12+ default).
oc apply -f alerts/bsod-risk-recording-rules.yaml   # bsod:fleet_evidence_completeness:ratio
oc apply -f alerts/bsod-risk-prometheusrules.yaml   # BSODRisk_FleetEvidenceIncomplete, BSODRisk_ExporterCollectionFailing
```

**ACM policy inclusion:** the PrometheusRule/recording-rule changes above ship
via `acm/bsod-risk-policy.yaml` alongside every other alert this framework
manages fleet-wide -- an exporter's *alert* silently missing from 3 of 12
managed clusters reproduces the exact "coverage gap" problem this component
exists to detect. The Deployment/Service/ServiceMonitor/RBAC/NetworkPolicy
above are **cluster-local, with no ACM equivalent** -- this repo's
`ConfigurationPolicy` templates enforce CRs (PrometheusRule, ConfigMap)
consumed by Prometheus, not arbitrary namespaced workloads with a per-cluster
image-pull/network posture, and every other per-cluster workload this
framework ships (`windows-exporter/`, `tekton/`) is likewise `oc apply`'d
directly rather than ACM-templated. This also means the exporter works
standalone with **zero RHACM dependency** on any single cluster -- not every
customer runs RHACM at all.

Verify the pod is running and serving metrics:

```bash
oc -n openshift-cnv get pods -l app.kubernetes.io/name=bsod-fleet-exporter
oc -n openshift-cnv exec deploy/bsod-fleet-exporter -- python3 -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/metrics').read().decode())"
```

**Then verify the NetworkPolicy is actually enforced** (security-review
finding, 2026-08-04) -- `oc apply` succeeding only means the API server
accepted the object, not that the CNI enforces it. Confirm a pod that is
*not* Prometheus cannot reach `:8080`, from a different namespace:

```bash
oc run np-probe --rm -i --restart=Never -n default \
  --image=registry.access.redhat.com/ubi9-minimal:latest -- \
  timeout 5 bash -c \
  'echo > /dev/tcp/bsod-fleet-exporter.openshift-cnv.svc.cluster.local/8080' \
  && echo "FAIL: reachable -- NetworkPolicy is not enforced or not applied" \
  || echo "OK: connection blocked, NetworkPolicy is enforced"
```

If this prints `FAIL`, either the NetworkPolicy was not applied
(`oc -n openshift-cnv get networkpolicy`) or the cluster's CNI does not
enforce `NetworkPolicy` at all (check with `oc get network.operator cluster
-o jsonpath='{.spec.defaultNetwork.type}{"\n"}'` -- OVN-Kubernetes, the OCP
4.12+ default, does; a non-default CNI may not). Treat a `FAIL` result the
same as a missing RBAC binding: block go-live until it prints `OK`.

## Configuration (container env vars)

| Env var | Default | Meaning |
|---|---|---|
| `EXPORTER_NAMESPACE` | unset (all namespaces) | Scope the audit to a single namespace |
| `EXPORTER_INTERVAL_SECONDS` | `300` | Seconds between collections |
| `EXPORTER_PORT` | `8080` | HTTP port serving `/metrics` and `/healthz` |
| `EXPORTER_METRICS_DIR` | `/var/run/bsod-metrics` (set to `/tmp/bsod-metrics` in `deployment.yaml`, matching its `readOnlyRootFilesystem` + single `/tmp` emptyDir) | Directory for the metrics file |
| `EXPORTER_SKIP_MICROCODE_PROBE` | `1` | Skip Gate 8's privileged `oc debug node/<name>` probe on every collection (see the exporter script's own header for the operational-cost rationale). Setting this to `0` does **not** work out of the box -- `bsod-fleet-exporter-sa` has no debug-pod/exec RBAC (see `exporter/service-account.yaml`); the probe will just fail permission checks (UNKNOWN, not a crash) unless that RBAC is granted separately first. |
| `EXPORTER_INTERVAL_FLOOR_VMS_TIER1` / `_SECONDS_TIER1` | `500` / `300` | See "Interval vs. fleet size" below. Not an operator-facing tuning knob in normal use -- env-overridable only so tests can exercise both tiers without a real large fleet. |
| `EXPORTER_INTERVAL_FLOOR_VMS_TIER2` / `_SECONDS_TIER2` | `2000` / `900` | Same as above, second tier. |

## Metrics emitted

- `bsod_evidence_completeness_percent{namespace,vm}` -- gauge, 0-100. Pure
  passthrough of `cnv-win-bsod-audit.sh --json`'s own `vm_record.evidence_completeness`
  field; never re-derived here. **Per-VM convenience/dashboard gauge only** --
  not the recording rule's input (see the next two metrics for that).
- `bsod_vm_checks_assessed{namespace,vm}` -- gauge, count of checks that
  reached a verdict (FAIL/WARN/PASS) this collection. Passthrough of
  `vm_record.assessed_count`.
- `bsod_vm_checks_total{namespace,vm}` -- gauge, count of checks attempted
  this collection (`assessed_count + unassessed_count`, both exact integers
  -- not reverse-derived from the rounded percent above).
- `bsod_vm_risk_tier{namespace,vm,tier}` -- gauge, always `1` (one active-tier
  series per VM; the other five tier values are never emitted at `0` for that
  VM). **R-27 Phase 2 (Issue K).** `tier` is `cnv-win-bsod-audit.sh`'s own
  `risk_tier()` value (`PASS|CRITICAL|HIGH|MEDIUM|LOW`), **except** this
  exporter overrides it to `UNKNOWN` whenever `assessed_count==0` for that VM
  this collection -- a tier computed from zero evidence is not a real
  verdict. Final six-value Prometheus vocabulary:
  `UNKNOWN|PASS|CRITICAL|HIGH|MEDIUM|LOW`, pinned by a drift-guard assertion
  in `tests/test_bash_fleet_exporter.sh` that fails if `risk_tier()` ever
  grows a 7th value.
- `bsod_vm_finding_count{namespace,vm,severity}` -- gauge, `severity` is one
  of `fail|warn|unknown`. **R-27 Phase 2 (Issue K).** Pure passthrough of
  `vm_record.fail_count`/`warn_count`; `unknown` reuses the same
  `unassessed_count` already exported via `bsod_vm_checks_total`'s
  denominator -- no separate bash field for it.
- `bsod_evidence_exporter_last_collection_timestamp_seconds` -- gauge, exporter's own health
- `bsod_evidence_exporter_last_collection_success` -- gauge 0/1, exporter's own health
- `bsod_evidence_exporter_interval_below_recommended` -- gauge 0/1, see
  "Interval vs. fleet size" below

Deliberately **no fleet-level metric** is emitted here -- see
`alerts/bsod-risk-recording-rules.yaml`'s `bsod:fleet_evidence_completeness:ratio`
recording rule, which derives the fleet aggregate via `sum(bsod_vm_checks_assessed)
/ sum(bsod_vm_checks_total)` over whatever VMs are currently reporting. This is
checks-**weighted** (unlike an earlier version of this rule, which used an
unweighted `avg()` over the percent gauge above and could disagree with the
audit script's own weighted figure) -- it now agrees with
`cnv-win-bsod-audit.sh --json`'s own `summary.evidence_completeness_pct` for
the same input by construction. See
`shared/evidence-completeness-thresholds.json`'s `_units` field for the full
rationale.

**R-27 Phase 2 scope note:** `bsod_vm_risk_tier`/`bsod_vm_finding_count` ship
as metrics only -- no new alert, recording rule, or dashboard panel this
phase (deferred until there is live data to calibrate thresholds against).

## Alerting

Two alerts work together, because they catch different failure modes:

- **`BSODRisk_FleetEvidenceIncomplete`** (`alerts/bsod-risk-prometheusrules.yaml`)
  -- fires when `bsod:fleet_evidence_completeness:ratio` drops below the
  configured threshold (`shared/evidence-completeness-thresholds.json`'s
  `fleet_warn_below_pct`, default 80%) for 30m. A **coverage** signal ("we
  might be blind to risk"), never a BSOD-trigger claim.
- **`BSODRisk_ExporterCollectionFailing`** (same file) -- fires when
  `bsod_evidence_exporter_last_collection_success` is `0` for 15m: the
  exporter pod is alive and answering scrapes, but every collection attempt
  is failing (RBAC narrowed, apiserver auth expired, script crashing).
  `bsod:fleet_evidence_completeness:ratio` alone cannot distinguish this from
  a healthy exporter with a genuinely improving fleet, since a scrape of a
  crash-looping collector still returns the *last successfully written*
  per-VM values until they go Prometheus-stale.

A third, **standard Prometheus self-monitoring** query is the companion to
both -- not implemented as a rule here because it needs no new code, only a
dashboard panel or a direct alert on it if desired:

```promql
up{job="bsod-fleet-exporter"} == 0
```

This catches "the pod is gone entirely" (crash-looped past its restart
budget, OOMKilled, node drained) -- a case `BSODRisk_ExporterCollectionFailing`
cannot catch, since that alert's own metric goes Prometheus-stale (not `0`)
once the pod itself stops responding to scrapes.

## Interval vs. fleet size

Re-running the full `--all-namespaces` audit on a fixed interval, forever, is
this framework's first continuously-scheduled apiserver-dependent workload.
`EXPORTER_INTERVAL_SECONDS=60` against a 5,000-VM fleet is not stopped by
anything at startup -- fleet size is not known until *after* the first
collection completes, so a hard startup refusal has a chicken-and-egg problem
and would still need an override escape hatch for an operator who knows their
apiserver can take it (making it behaviorally identical to a warning, just
with more code and one more failure mode). Instead, after each real
collection, the exporter compares `EXPORTER_INTERVAL_SECONDS` against the
fleet size it just observed and logs a WARN plus sets
`bsod_evidence_exporter_interval_below_recommended` to `1` when the interval
is below the recommended floor:

| Fleet size (`total_vms`) | Recommended `EXPORTER_INTERVAL_SECONDS` floor |
|---|---|
| < 500 | no recommendation (300s default is fine) |
| ≥ 500 | ≥ 300s |
| ≥ 2000 | ≥ 900s (15m) |

The recommended floors above are conservative starting points. Increase the
interval if collection duration approaches the scrape interval.

## Why a Deployment, not a CronJob

R-27's own action text says "Scheduled CronJob/Tekton emitting...", but
Prometheus scrapes are pull-based: a CronJob's Pod exists only for the
duration of one run and is gone by the time Prometheus's own scrape interval
fires, unless coordinated to the second. This Deployment runs a single
long-lived Pod that loops internally (`EXPORTER_INTERVAL_SECONDS`) and always
has something listening for the next scrape -- functionally "scheduled
export", just via an in-process timer instead of a Kubernetes-level
schedule. See `deployment.yaml`'s own comments for the full reasoning,
including why `replicas: 1` (no HA) is deliberate.
