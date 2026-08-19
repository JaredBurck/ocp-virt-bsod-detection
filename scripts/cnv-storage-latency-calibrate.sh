#!/usr/bin/env bash
#
# cnv-storage-latency-calibrate.sh
# -----------------------------------------------------------------------------
# Sample a cluster's ACTUAL Windows-VM storage latency distribution -- BOTH
# read and write, graded on the worse direction, matching what the alerts
# evaluate -- and compare it against shared/storage-latency-thresholds.json.
#
# F-01 (v0.25.0 peer review): this sampled reads only until v0.26.0, so any
# figures recorded before then describe the read path alone.
#
# WHY THIS EXISTS (H-5)
#
# The storage alert thresholds (0.5 s WARN / 1.0 s CRITICAL) were adopted by
# operator decision in v0.15.0 and shipped with `_calibration_status:
# OUTSTANDING` -- no cluster had ever been measured. The original validation
# cluster's fixture VMs used blank disks, so rate(kubevirt_vmi_storage_iops_
# read_total) was 0 and no distribution could be sampled at all. That gap
# survived three review rounds, and it is why the ACM policy ships `inform`
# rather than `enforce`.
#
# Documenting the PromQL in a runbook was not enough: it asks every operator to
# transcribe queries correctly and interpret percentiles consistently. This
# turns "please calibrate before fleet rollout" into one command that any
# cluster -- including a customer's production one -- can run and hand back.
#
# WHAT IT CAN AND CANNOT TELL YOU
#
#   CAN:    whether the shipped thresholds false-positive on THIS cluster's
#           real workload, and how much headroom exists.
#   CANNOT: whether they will catch a real pre-BSOD storage brownout. That
#           needs a cluster that has actually had one. Absence of an alert on
#           a healthy cluster is not evidence the alert works; proving the
#           recording-rule -> alert -> Alertmanager path fires is a separate
#           exercise (see docs/operator-runbook.md, "Validating the alerting
#           path"), done by temporarily lowering the threshold against real
#           traffic rather than by waiting for a brownout.
#
# Requires: oc (logged in), jq, curl. Reads Thanos via the openshift-monitoring
# route; needs permission to GET that route and query metrics.
#
# Usage:
#   ./scripts/cnv-storage-latency-calibrate.sh [--window 7d] [--namespace NS]
#                                              [--json out.json]
#
# EXIT CODE CONTRACT (v0.16.0 #9) -- matches analyze.py's documented 0/1/2
# convention, distinguishing "this cluster has a real finding" (1) from
# "the calibration could not be completed at all" (2). Conflating the two
# previously meant a caller couldn't tell "storage latency exceeds warn" from
# "Thanos was unreachable" without parsing stdout text.
#   0 -- WITHIN_THRESHOLDS: peak observed latency sits under WARN.
#   1 -- EXCEEDS_WARN / EXCEEDS_CRITICAL: a genuine calibration finding.
#   2 -- acquisition/inconclusive: pre-flight failure, Thanos query failure,
#        no active storage-I/O series in the window, or no verdict could be
#        reached at all (UNKNOWN) -- this is NOT a calibration result.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WINDOW="24h"
NAMESPACE=""
JSON_OUT=""

usage() {
  cat <<'EOF'
Usage: cnv-storage-latency-calibrate.sh [options]

  --window <dur>     Lookback window (default 24h). Use 7d or 30d for a
                     representative sample; a short window on a quiet cluster
                     measures idle, not workload.
  --namespace <ns>   Restrict to one namespace (default: all Windows VMs).
  --json <file>      Also write machine-readable results.
  -h, --help         This help.

Interpreting the result:
  The thresholds exist to predict a TAIL event -- an individual I/O breaching
  the ~60s VirtIO IoTimeoutValue during a storage brownout. They are therefore
  deliberately far below 60s. A p95 comfortably under the WARN threshold means
  no false positives; it does NOT by itself mean the alert would catch a real
  brownout.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --window) WINDOW="$2"; shift 2 ;;
    --namespace|-n) NAMESPACE="$2"; shift 2 ;;
    --json) JSON_OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

command -v oc   >/dev/null 2>&1 || { echo "oc is required" >&2; exit 2; }
command -v jq   >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

THRESHOLDS="$REPO_ROOT/shared/storage-latency-thresholds.json"
[ -f "$THRESHOLDS" ] || THRESHOLDS="/usr/share/bsod-detection/shared/storage-latency-thresholds.json"
if [ ! -f "$THRESHOLDS" ]; then
  echo "cannot find shared/storage-latency-thresholds.json" >&2; exit 2
fi
WARN=$(jq -r '.sustained_warn_seconds'      "$THRESHOLDS")
CRIT=$(jq -r '.sustained_critical_seconds'  "$THRESHOLDS")
BURST=$(jq -r '.burst_seconds'              "$THRESHOLDS")
IOTIMEOUT=$(jq -r '.virtio_io_timeout_seconds' "$THRESHOLDS")

TOKEN=$(oc whoami -t 2>/dev/null) || { echo "not logged in (oc whoami -t failed)" >&2; exit 2; }
HOST=$(oc get route -n openshift-monitoring thanos-querier -o jsonpath='{.spec.host}' 2>/dev/null)
if [ -z "$HOST" ]; then
  echo "could not resolve the thanos-querier route in openshift-monitoring." >&2
  echo "Cluster monitoring may not be enabled, or you lack permission to read the route." >&2
  exit 2
fi

# #6 (v0.16.0): this curl runs OUTSIDE the cluster against the thanos-querier
# ROUTE (edge-terminated by the OpenShift router), not a pod-to-service call
# -- that route's certificate is signed by the cluster's INGRESS CA, not the
# internal openshift-service-ca.crt used for pod-to-pod traffic (verified on
# a live cluster: the route's cert issuer matches
# openshift-config-managed/default-ingress-cert exactly, not
# openshift-service-ca.crt). Trust that bundle explicitly instead of `-k`
# skipping verification, which would also silently accept an interposed
# endpoint if the operator's DNS/route were hijacked.
CA_BUNDLE=$(mktemp)
trap 'rm -f "$CA_BUNDLE"' EXIT
if ! oc get configmap default-ingress-cert -n openshift-config-managed \
    -o jsonpath='{.data.ca-bundle\.crt}' >"$CA_BUNDLE" 2>/dev/null \
    || [ ! -s "$CA_BUNDLE" ]; then
  echo "could not read openshift-config-managed/default-ingress-cert (the" >&2
  echo "router's CA bundle) -- cannot verify the thanos-querier route's TLS" >&2
  echo "certificate. Refusing to fall back to skipping verification." >&2
  exit 2
fi

_sel=""
[ -n "$NAMESPACE" ] && _sel="{namespace=\"$NAMESPACE\"}"

# Average seconds-per-op, per VM/drive, over a 5m rate window, for EACH
# direction. These are the same expressions the recording rules and alerts use
# -- calibrating anything else would measure a quantity the alerts do not
# evaluate.
#
# F-01 (v0.25.0 peer review): this script sampled only the READ counters until
# v0.26.0, so the figures recorded in shared/storage-latency-thresholds.json's
# _calibration_observed describe reads alone -- including the 3.0x margin. The
# alerts now grade the worst direction, so the calibration has to see both or
# it is measuring something narrower than what fires.
RLAT="(sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_read_times_seconds_total${_sel}[5m])) / sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_read_total${_sel}[5m])))"
WLAT="(sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_write_times_seconds_total${_sel}[5m])) / sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_write_total${_sel}[5m])))"
# Only consider series doing real work; a VM at ~0 IOPS produces a meaningless
# (and wildly noisy) ratio that would dominate any percentile.
RACTIVE="(sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_read_total${_sel}[5m])) > 0.5)"
WACTIVE="(sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_write_total${_sel}[5m])) > 0.5)"

# Worst-direction latency, mirroring the bsod:vmi_disk_latency:worst_1h
# recording rule: label_replace stamps a distinguishing label so `or` is a
# genuine union (rather than a left-preferring merge that would DROP a
# one-direction disk), then max by() collapses the pair.
#
# Each direction carries its OWN activity gate inside the union, which is why
# there is no separate $ACTIVE term below any more. That matters beyond tidiness:
# gating the whole thing on read IOPS -- as this script did until v0.26.0 --
# reported a write-busy Windows VM (pagefile and log churn, the exact workload
# that precedes a storage-triggered bugcheck) as "NO ACTIVE SERIES" and exited 2.
# Per-direction gating also keeps an idle-read/busy-write disk from being scored
# on its meaningless read ratio.
LAT="max by (name, namespace, drive) (label_replace(($RLAT and $RACTIVE), \"direction\", \"read\", \"\", \"\") or label_replace(($WLAT and $WACTIVE), \"direction\", \"write\", \"\", \"\"))"

query() {
  curl -s --max-time 90 --cacert "$CA_BUNDLE" -H "Authorization: Bearer $TOKEN" \
    --get "https://$HOST/api/v1/query" --data-urlencode "query=$1" 2>/dev/null
}
scalar() {
  local r; r=$(query "$1")
  if [ -z "$r" ] || [ "$(jq -r '.status // "error"' <<<"$r")" != "success" ]; then
    echo "ERR"; return 1
  fi
  jq -r '.data.result[0].value[1] // "none"' <<<"$r"
}

echo "=============================================================="
echo " Storage latency calibration (read + write, worst direction)"
echo " window: $WINDOW   namespace: ${NAMESPACE:-<all>}"
echo " thresholds: WARN ${WARN}s  CRITICAL ${CRIT}s  BURST ${BURST}s"
echo "=============================================================="

ACTIVE_SERIES=$(scalar "count($LAT)")
if [ "$ACTIVE_SERIES" = "ERR" ]; then
  echo "  ERROR: Thanos query failed (auth, RBAC, or monitoring not available)."
  echo "  This is NOT a calibration result -- do not record it as one."
  exit 2
fi
if [ "$ACTIVE_SERIES" = "none" ] || [ "${ACTIVE_SERIES%%.*}" -eq 0 ] 2>/dev/null; then
  echo "  NO ACTIVE SERIES: no VM exceeded 0.5 read or write IOPS in the window."
  echo
  echo "  This means the cluster has no measurable Windows storage workload --"
  echo "  NOT that latency is healthy. Calibrating on this would record idle as"
  echo "  if it were normal. Run against a cluster carrying real Windows I/O."
  exit 2
fi
echo "  active series (>0.5 read or write IOPS): $ACTIVE_SERIES"
echo

# quantile_over_time returns one value PER SERIES. Taking result[0] would pick
# an arbitrary disk -- and since Prometheus does not guarantee series ordering,
# each percentile could come from a DIFFERENT disk, which is how the first run
# of this script reported p99 (0.0040) BELOW p95 (0.0057): impossible within
# one series, and a giveaway that the values were unrelated.
#
# max() over the per-series quantiles answers the question calibration actually
# needs: "how bad does the WORST-behaving disk get at this percentile", which
# is the series that would trip the alert first.
P50=$(scalar "max(quantile_over_time(0.50, ($LAT)[$WINDOW:5m]))")
P95=$(scalar "max(quantile_over_time(0.95, ($LAT)[$WINDOW:5m]))")
P99=$(scalar "max(quantile_over_time(0.99, ($LAT)[$WINDOW:5m]))")
MAXV=$(scalar "max(max_over_time(($LAT)[$WINDOW:5m]))")

fmt() { [ "$1" = "none" ] || [ "$1" = "ERR" ] && { printf '%s' "$1"; return; }; awk -v v="$1" 'BEGIN{printf "%.4f", v}'; }
P50F=$(fmt "$P50"); P95F=$(fmt "$P95"); P99F=$(fmt "$P99"); MAXF=$(fmt "$MAXV")

printf '  p50 : %8s s/op\n' "$P50F"
printf '  p95 : %8s s/op\n' "$P95F"
printf '  p99 : %8s s/op\n' "$P99F"
printf '  max : %8s s/op\n' "$MAXF"
echo

verdict="UNKNOWN"
if [ "$MAXV" != "none" ] && [ "$MAXV" != "ERR" ]; then
  margin=$(awk -v w="$WARN" -v m="$MAXV" 'BEGIN{ if (m>0) printf "%.1f", w/m; else print "inf" }')
  over_warn=$(awk -v w="$WARN" -v m="$MAXV" 'BEGIN{print (m>=w)?1:0}')
  over_crit=$(awk -v c="$CRIT" -v m="$MAXV" 'BEGIN{print (m>=c)?1:0}')
  if [ "$over_crit" = "1" ]; then
    verdict="EXCEEDS_CRITICAL"
    echo "  VERDICT: observed max ($MAXF) is AT OR ABOVE the CRITICAL threshold ($CRIT)."
    echo "    Either this cluster has a real storage problem, or the thresholds are"
    echo "    too sensitive for this backend. Investigate before fleet rollout --"
    echo "    do not simply raise the threshold to silence it."
  elif [ "$over_warn" = "1" ]; then
    verdict="EXCEEDS_WARN"
    echo "  VERDICT: observed max ($MAXF) is AT OR ABOVE the WARN threshold ($WARN)."
    echo "    Expect alerts on normal operation. Investigate the peak before"
    echo "    rolling out with enforce."
  else
    verdict="WITHIN_THRESHOLDS"
    echo "  VERDICT: no false positives -- peak sits ${margin}x under the WARN"
    echo "    threshold ($WARN s/op)."
    awk -v m="$margin" 'BEGIN{ if (m+0 < 3) print "    NOTE: margin is under 3x. A denser fleet could approach WARN\n    during simultaneous boot; re-check before scaling up." }'
  fi
fi
echo
echo "  Reference: these thresholds are deliberately far below the ${IOTIMEOUT}s"
echo "  VirtIO IoTimeoutValue. What causes MEMORY_MANAGEMENT (0x1A) is a TAIL"
echo "  spike during a brownout; an hourly mean anywhere near ${IOTIMEOUT}s means the"
echo "  guest has already bugchecked (KCS-7132512)."
echo
echo "  A clean result proves the thresholds do not FALSE-POSITIVE here. It does"
echo "  NOT prove they would CATCH a real brownout -- this cluster has not had"
echo "  one. Those are different claims; record only the one you measured."

if [ -n "$JSON_OUT" ]; then
  jq -n --arg window "$WINDOW" --arg ns "${NAMESPACE:-all}" \
        --arg p50 "$P50F" --arg p95 "$P95F" --arg p99 "$P99F" --arg max "$MAXF" \
        --arg series "$ACTIVE_SERIES" --arg verdict "$verdict" \
        --argjson warn "$WARN" --argjson crit "$CRIT" --argjson burst "$BURST" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{timestamp:$ts, window:$window, namespace:$ns, active_series:($series|tonumber?),
      direction_sampled:"read+write (graded on the worse direction, as the alerts do)",
      observed:{p50:($p50|tonumber?), p95:($p95|tonumber?), p99:($p99|tonumber?), max:($max|tonumber?)},
      thresholds:{warn:$warn, critical:$crit, burst:$burst},
      verdict:$verdict,
      caveat:"Proves absence of false positives on this workload only. Does NOT prove the alert would catch a real storage brownout."}' \
    > "$JSON_OUT"
  echo
  echo "  JSON written: $JSON_OUT"
fi

case "$verdict" in
  WITHIN_THRESHOLDS) exit 0 ;;
  EXCEEDS_WARN|EXCEEDS_CRITICAL) exit 1 ;;
  *)
    # UNKNOWN: active series existed but no percentile/max query resolved to
    # a usable value. Acquisition-inconclusive, not a finding -- same class
    # as the ERR/no-active-series cases above.
    echo
    echo "  VERDICT: UNKNOWN -- percentile/max queries did not resolve to a"
    echo "    usable value. This is NOT a calibration result -- do not record"
    echo "    it as one."
    exit 2
    ;;
esac
