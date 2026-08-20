#!/usr/bin/env bash
# prom-query.sh -- minimal, fail-closed Thanos/Prometheus query helper.
#
# F-05 (v0.25.0 peer review). Gate 11 emitted UNKNOWN unconditionally for every
# running VM with a PVC-backed disk: "storage latency NOT measured -- the
# cluster API cannot read guest I/O latency". True of the *cluster API*, but the
# framework already ships recording rules that compute exactly this, and the
# monitoring stack that answers them is present on every OCP cluster. The gate
# was declining to look at data sitting one HTTP request away.
#
# Combined with UNKNOWN scoring 0 since R-21, the practical effect was that
# storage latency -- the second-ranked BSOD mechanism in this framework's own
# KCS catalogue (7132512) -- contributed nothing to the customer-facing risk
# tier under any circumstances.
#
# Extracted rather than inlined because scripts/cnv-storage-latency-calibrate.sh
# already carried this exact plumbing (route lookup, bearer token, CA bundle,
# explicit refusal to fall back to -k) as the repo's ONLY HTTP client. Two
# copies of a security-sensitive TLS path is one too many.
#
# CONTRACT: every function fails closed. A missing route, an unavailable token,
# a TLS problem, a non-200, a malformed body -- all return non-zero with no
# output, so a caller that forgets to check gets nothing rather than something
# wrong. Callers are expected to translate that into UNKNOWN, never into a pass.
#
# Consumers: scripts/cnv-win-bsod-audit.sh (Gate 11).

# pq_available: 0 if a query can be attempted, 1 otherwise.
#
# Sets PQ_HOST / PQ_TOKEN / PQ_CA on success. Idempotent -- the discovery cost
# (two oc calls plus a temp file) is paid once per audit run, not once per VM.
# PQ_UNAVAILABLE_REASON is this library's RETURN VALUE for "why not" -- bash
# functions cannot return strings, so the caller (Gate 11) reads it to put the
# actual cause in its UNKNOWN message instead of a generic "not measured".
# This file is linted standalone, so that consumer is invisible to the linter.
# shellcheck disable=SC2034
PQ_HOST=""
PQ_TOKEN=""
PQ_CA=""
PQ_INIT_DONE=0
PQ_UNAVAILABLE_REASON=""

pq_available() {
  [ "${BSOD_SKIP_PROM_QUERY:-0}" = "1" ] && {
    PQ_UNAVAILABLE_REASON="disabled via BSOD_SKIP_PROM_QUERY=1"
    return 1
  }
  if [ "$PQ_INIT_DONE" -eq 1 ]; then
    [ -n "$PQ_HOST" ] && return 0 || return 1
  fi
  PQ_INIT_DONE=1

  command -v curl >/dev/null 2>&1 || {
    PQ_UNAVAILABLE_REASON="curl not installed"
    return 1
  }

  PQ_TOKEN=$(oc whoami -t 2>/dev/null)
  [ -n "$PQ_TOKEN" ] || {
    PQ_UNAVAILABLE_REASON="no API token (oc whoami -t returned nothing)"
    return 1
  }

  PQ_HOST=$(oc get route -n openshift-monitoring thanos-querier \
    -o jsonpath='{.spec.host}' 2>/dev/null)
  [ -n "$PQ_HOST" ] || {
    PQ_UNAVAILABLE_REASON="thanos-querier route not found in openshift-monitoring"
    PQ_HOST=""
    return 1
  }

  # The ingress CA, so certificate verification is real. Deliberately no -k
  # fallback: this call carries a bearer token with the caller's full API
  # privileges, and skipping verification to make a diagnostic convenient is
  # not a trade this framework makes. Same stance as
  # cnv-storage-latency-calibrate.sh.
  PQ_CA=$(mktemp 2>/dev/null) || {
    PQ_UNAVAILABLE_REASON="could not create temp file for the CA bundle"
    PQ_HOST=""
    return 1
  }
  oc get configmap default-ingress-cert -n openshift-config-managed \
    -o jsonpath='{.data.ca-bundle\.crt}' > "$PQ_CA" 2>/dev/null
  if [ ! -s "$PQ_CA" ]; then
    rm -f "$PQ_CA"
    PQ_CA=""
    PQ_HOST=""
    PQ_UNAVAILABLE_REASON="could not read the ingress CA bundle (openshift-config-managed/default-ingress-cert)"
    return 1
  fi
  return 0
}

pq_cleanup() { [ -n "$PQ_CA" ] && rm -f "$PQ_CA"; PQ_CA=""; }

# pq_scalar <promql> -- print the first result's value, or nothing.
#
# Returns 1 on any failure INCLUDING an empty result set, so "the query worked
# and matched no series" and "the query failed" are both non-zero. That is
# deliberate for this caller: Gate 11 must not read "no series" as "latency is
# fine" -- absence of data is UNKNOWN, which is exactly the distinction this
# framework exists to preserve.
pq_scalar() {
  local query="$1" body status
  pq_available || return 1
  body=$(curl -s --max-time "${BSOD_PROM_TIMEOUT:-20}" --cacert "$PQ_CA" \
    -H "Authorization: Bearer $PQ_TOKEN" \
    --get "https://$PQ_HOST/api/v1/query" \
    --data-urlencode "query=$query" 2>/dev/null) || return 1
  [ -n "$body" ] || return 1
  status=$(printf '%s' "$body" | jq -r '.status // "error"' 2>/dev/null)
  [ "$status" = "success" ] || return 1
  local value
  value=$(printf '%s' "$body" | jq -r '.data.result[0].value[1] // empty' 2>/dev/null)
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

# pq_vm_worst_latency <namespace> <vm> -- worst-direction seconds/op, or nothing.
#
# Prefers the shipped recording rule and falls back to computing the same
# quantity from the raw KubeVirt counters.
#
# The fallback is not redundancy for its own sake: the recording rules live in a
# PrometheusRule CR an operator has to deploy, and on a cluster that has not
# deployed it `bsod:vmi_disk_latency:worst_1h` returns nothing while the raw
# counters are right there. Confirmed on the validation cluster, which had 5
# live KubeVirt storage series and 0 recording-rule series. Querying only the
# rule would have made this gate silently useless on exactly the clusters that
# have not adopted the alerting layer yet -- i.e. the ones most likely to be
# running an audit for the first time.
#
# The fallback expression MUST stay equivalent to the recording rule's;
# scripts/ci/validate-shared-thresholds.py binds them.
pq_vm_worst_latency() {
  local ns="$1" vm="$2" value

  value=$(pq_scalar "max(bsod:vmi_disk_latency:worst_1h{namespace=\"$ns\",name=\"$vm\"})") \
    && { printf '%s' "$value"; return 0; }

  # Same worst-direction union as the recording rule: label_replace stamps a
  # distinguishing label so `or` is a genuine union rather than a
  # left-preferring merge (which would DROP a disk doing I/O in only one
  # direction), then max by() collapses it.
  local read_expr write_expr
  read_expr="(sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_read_times_seconds_total{namespace=\"$ns\",name=\"$vm\"}[1h])) / sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_read_total{namespace=\"$ns\",name=\"$vm\"}[1h]))) and sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_read_total{namespace=\"$ns\",name=\"$vm\"}[1h])) > 0"
  write_expr="(sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_write_times_seconds_total{namespace=\"$ns\",name=\"$vm\"}[1h])) / sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_write_total{namespace=\"$ns\",name=\"$vm\"}[1h]))) and sum by (name, namespace, drive) (rate(kubevirt_vmi_storage_iops_write_total{namespace=\"$ns\",name=\"$vm\"}[1h])) > 0"

  pq_scalar "max(max by (name, namespace, drive) (label_replace($read_expr, \"direction\", \"read\", \"\", \"\") or label_replace($write_expr, \"direction\", \"write\", \"\", \"\")))"
}
