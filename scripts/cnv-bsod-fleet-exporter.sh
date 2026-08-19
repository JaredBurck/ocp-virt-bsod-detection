#!/usr/bin/env bash
# cnv-bsod-fleet-exporter.sh -- Continuous evidence-completeness metrics exporter
#
# Issue K (docs/info/peer-reviews/v0.19.0/issues/gitlab-issue-drafts-open-after-
# remediation.md): R-21 (v0.19.0) made per-VM evidence completeness ("of the
# checks we tried to run on this VM, how many actually reached a verdict") a
# first-class REPORTED axis in scripts/cnv-win-bsod-audit.sh and
# insights-rules/, but nothing exported it as a metric or made it alertable.
#
# THIS IS R-27's EXPORT PATH, NOT A SECOND ONE. Issue K's 4th acceptance
# criterion is explicit: "Coordinated with R-27 rather than building a second
# export path." R-27 (MASTER-remediation-plan.md: "Scheduled CronJob/Tekton
# emitting per-VM gate rollups as OpenMetrics/textfile") was deferred with no
# design, not implemented elsewhere -- so this loop + scripts/lib/
# serve-metrics.py's tiny HTTP server IS that design's first concrete
# instance, scoped for now to the one metric family Issue K asks for
# (evidence completeness). A later gate-rollup metric family (risk tier,
# per-severity finding counts) is a pure additive change to THIS SAME
# emission pass -- not a new Deployment, RBAC, or ServiceMonitor.
#
# DELIBERATELY NO FLEET-LEVEL PRE-AGGREGATION HERE. This script emits only
# per-VM gauges; alerts/bsod-risk-recording-rules.yaml's
# bsod:fleet_evidence_completeness:ratio derives the fleet figure via a plain
# PromQL sum()/sum() over whatever VMs are currently reporting. Matches this
# repo's existing convention for every other multi-VM aggregate (e.g.
# bsod:vmi_disk_latency:avg_1h is derived from raw _total counters via a
# recording rule, never pre-averaged in a collector) -- the exporter's job is
# to relabel what cnv-win-bsod-audit.sh already computed per VM, not to
# invent a second, only-here fleet statistic that can silently disagree with
# whatever R-27 eventually rolls up for other gate data.
#
# WHY RAW COUNTS (bsod_vm_checks_assessed/_total), NOT JUST THE PERCENT: an
# architectural review (2026-08-04) found that deriving the fleet figure via
# avg(bsod_evidence_completeness_percent) -- an unweighted mean of per-VM
# percentages -- disagrees with cnv-win-bsod-audit.sh --json's own
# summary.evidence_completeness_pct (checks-weighted: sum(assessed)/
# sum(total)) for the identical input whenever VMs have different check
# counts, and is the statistically wrong choice for a coverage SLO: a fleet
# of one well-covered VM and one nearly-blind VM would read as "50%
# coverage" regardless of how many actual checks each one represents. Raw
# per-VM counts let the recording rule compute the SAME weighted ratio
# PromQL-side via sum()/sum(), so the two numbers agree by construction. The
# percent gauge below is kept purely as a per-VM convenience/dashboard value
# (still a pure passthrough) -- it is not the recording rule's input.
#
# Read-only: this script never mutates a VM, a node, or any cluster object --
# it only runs the same audit an operator would run by hand, on a timer, and
# reshapes its own JSON output.
#
# Usage (inside the exporter container -- see Dockerfile.gate-exporter):
#   ./cnv-bsod-fleet-exporter.sh
#
# Environment:
#   EXPORTER_NAMESPACE            Single namespace to audit (default: all
#                                 namespaces, via --all-namespaces)
#   EXPORTER_INTERVAL_SECONDS     Seconds between collections (default: 300)
#   EXPORTER_PORT                 HTTP port to serve /metrics on (default: 8080)
#   EXPORTER_METRICS_DIR          Directory for the metrics file (default:
#                                 /var/run/bsod-metrics)
#   EXPORTER_SKIP_MICROCODE_PROBE Default 1 (skip Gate 8's node microcode
#                                 probe -- see the note below).
#   AUDIT_SCRIPT                 Path to cnv-win-bsod-audit.sh (default:
#                                 /scripts/cnv-win-bsod-audit.sh, matching the
#                                 exporter image's layout; falls back to a
#                                 sibling of this script for local testing)
#
# Metrics served on :$EXPORTER_PORT/metrics:
#   bsod_evidence_completeness_percent{namespace,vm}   gauge, 0-100 (per-VM convenience only)
#   bsod_vm_checks_assessed{namespace,vm}               gauge, checks that reached a verdict
#   bsod_vm_checks_total{namespace,vm}                  gauge, checks attempted (assessed+unassessed)
#   bsod_vm_risk_tier{namespace,vm,tier}                gauge, always 1 (single active-tier
#     series per VM). tier is cnv-win-bsod-audit.sh's own risk_tier() value
#     (PASS|CRITICAL|HIGH|MEDIUM|LOW), EXCEPT this exporter overrides it to
#     UNKNOWN whenever assessed_count==0 for that VM -- see the R-27 PHASE 2
#     TIER VOCABULARY note below.
#   bsod_vm_finding_count{namespace,vm,severity}        gauge, severity=fail|warn|unknown
#     (fail_count/warn_count/unassessed_count, pure passthrough)
#   bsod_evidence_exporter_last_collection_timestamp_seconds  gauge
#   bsod_evidence_exporter_last_collection_success            gauge, 0/1
#   bsod_evidence_exporter_interval_below_recommended         gauge, 0/1 (see the
#     INTERVAL-VS-FLEET-SIZE note below)
# (These metric names are the single source of truth this script emits --
# scripts/ci/validate-metric-names.py's check_evidence_completeness_metric_name()
# fails CI if the recording rule that reads bsod_vm_checks_assessed/_total
# drifts from these literals.)
#
# R-27 PHASE 2 TIER VOCABULARY (docs/design/r-27-fleet-gate-verdict-exporter.md
# §6.5/§11): bsod_vm_risk_tier's raw tier values are a pure passthrough of
# cnv-win-bsod-audit.sh's risk_tier(), which only ever returns
# PASS|CRITICAL|HIGH|MEDIUM|LOW (no bash-side change here). This exporter adds
# exactly one piece of new logic on top: when a VM's assessed_count==0 (zero
# checks reached FAIL/WARN/PASS this collection -- e.g. RBAC denied every
# probe, or the VM was unreachable), the emitted tier is forced to UNKNOWN
# regardless of what risk_tier() itself reported for that VM, because a tier
# computed from zero evidence is not a real verdict. Final six-value
# Prometheus vocabulary: UNKNOWN|PASS|CRITICAL|HIGH|MEDIUM|LOW. This
# vocabulary is pinned by a drift-guard assertion in
# tests/test_bash_fleet_exporter.sh -- if risk_tier() ever grows a 7th value,
# that test fails instead of this exporter silently passing through a label
# no dashboard/alert expects.
#
# INTERVAL-VS-FLEET-SIZE (design doc docs/design/r-27-fleet-gate-verdict-
# exporter.md §6.9/§10.2/§11): a hard startup refusal below some interval was
# considered and rejected -- fleet size isn't known until AFTER the first
# collection (chicken-and-egg), and any hard block still needs an override
# escape hatch for an operator who knows their apiserver can take it, making
# it behaviorally identical to a loud warning with more code and one more
# failure mode. Implemented instead as a soft signal computed AFTER each
# real collection: EXPORTER_INTERVAL_SECONDS is compared against the
# recommended floor for the total_vms just observed
# (EXPORTER_INTERVAL_FLOOR_VMS_TIER1/2, EXPORTER_INTERVAL_FLOOR_SECONDS_TIER1/2
# below -- values match the design doc's own §6.9 numbers, not new ones), a
# WARN is logged, and bsod_evidence_exporter_interval_below_recommended is
# set to 1 so it is visible in Prometheus too, not just container logs.
#
# ACCURACY NOTE: EXPORTER_SKIP_MICROCODE_PROBE defaults to 1, matching
# tekton/bsod-gate-task.yaml's BSOD_SKIP_MICROCODE_PROBE=1 precedent, for the
# same reason -- this script runs unattended and on a timer (every 5 minutes
# by default), and Gate 8's probe spawns a privileged `oc debug node/<name>`
# pod on every AMD Family 1Ah node it checks. Doing that every interval,
# forever, across the whole fleet is a meaningfully different operational
# cost than doing it once for a manual audit. The trade-off: Gate 8 reports
# UNASSESSED instead of a real verdict when skipped, which is one more
# UNKNOWN in every AMD-node VM's denominator -- so the exported
# evidence-completeness percentage is intentionally scoped to "coverage among
# checks this exporter actually re-runs continuously" and will read slightly
# LOWER than a one-off manual `cnv-win-bsod-audit.sh` run with the probe
# enabled. Set EXPORTER_SKIP_MICROCODE_PROBE=0 to disable this skip and get
# full accuracy, at the cost of periodic privileged debug pods --
# RBAC NOTE (code-review finding, 2026-08-04): bsod-fleet-exporter-sa is
# bound only to the read-only bsod-audit-gate ClusterRole (see
# exporter/service-account.yaml), which grants no pods/exec, no debug-pod
# creation, and no nodes/proxy. That RBAC is deliberately NOT expanded for
# this override -- setting EXPORTER_SKIP_MICROCODE_PROBE=0 without also
# granting `oc debug node/<name>` permission to this ServiceAccount will not
# fail loudly; Gate 8's probe will simply fail permission checks the same way
# it degrades on any other unreachable node (UNKNOWN, not a crash, not a
# privilege escalation). Grant the additional RBAC first if you actually want
# this override to change Gate 8's verdict rather than just adding
# apiserver-visible noise for a probe that can never succeed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }

# --- Configuration (env-overridable) ---
EXPORTER_NAMESPACE="${EXPORTER_NAMESPACE:-}"
EXPORTER_INTERVAL_SECONDS="${EXPORTER_INTERVAL_SECONDS:-300}"
EXPORTER_PORT="${EXPORTER_PORT:-8080}"
EXPORTER_METRICS_DIR="${EXPORTER_METRICS_DIR:-/var/run/bsod-metrics}"
EXPORTER_SKIP_MICROCODE_PROBE="${EXPORTER_SKIP_MICROCODE_PROBE:-1}"
# See the module header's INTERVAL-VS-FLEET-SIZE note. Env-overridable only
# so tests can exercise both tiers without waiting for a real large fleet;
# not intended as an operator-facing tuning knob in normal use.
EXPORTER_INTERVAL_FLOOR_VMS_TIER1="${EXPORTER_INTERVAL_FLOOR_VMS_TIER1:-500}"
EXPORTER_INTERVAL_FLOOR_SECONDS_TIER1="${EXPORTER_INTERVAL_FLOOR_SECONDS_TIER1:-300}"
EXPORTER_INTERVAL_FLOOR_VMS_TIER2="${EXPORTER_INTERVAL_FLOOR_VMS_TIER2:-2000}"
EXPORTER_INTERVAL_FLOOR_SECONDS_TIER2="${EXPORTER_INTERVAL_FLOOR_SECONDS_TIER2:-900}"
METRICS_FILE="$EXPORTER_METRICS_DIR/metrics.prom"

if [ -n "${AUDIT_SCRIPT:-}" ]; then
  : # explicit override wins
elif [ -x "/scripts/cnv-win-bsod-audit.sh" ]; then
  AUDIT_SCRIPT="/scripts/cnv-win-bsod-audit.sh"
else
  AUDIT_SCRIPT="$SCRIPT_DIR/cnv-win-bsod-audit.sh"
fi

if [ ! -x "$AUDIT_SCRIPT" ]; then
  log "FATAL: audit script not found or not executable: $AUDIT_SCRIPT"
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  log "FATAL: jq is required"
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  log "FATAL: python3 is required (scripts/lib/serve-metrics.py)"
  exit 1
fi

mkdir -p "$EXPORTER_METRICS_DIR"

# write_metrics <vms_json> <collect_ok> <interval_below_recommended>
#
# Atomic write: temp file in the SAME directory (so the final `mv` is a
# same-filesystem rename, which POSIX guarantees is atomic) means a scrape
# racing this write via serve-metrics.py's per-request re-read either sees
# the complete old file or the complete new file, never a partial one.
#
# Per-VM gauges only, no fleet-level pre-aggregation -- see the module
# header for why (both for the "no second fleet statistic" reason and the
# raw-counts-not-a-percent reason).
write_metrics() {
  local vms_json="$1" collect_ok="$2" interval_below_recommended="${3:-0}"
  local tmp
  tmp=$(mktemp "$EXPORTER_METRICS_DIR/.metrics.XXXXXX")

  {
    echo "# HELP bsod_evidence_completeness_percent Per-VM evidence completeness (Issue K): of the checks cnv-win-bsod-audit.sh tried to run on this VM, the percentage that reached a verdict (FAIL/WARN/PASS) rather than UNKNOWN. 0-100. Pure passthrough of the audit script's own vm_record.evidence_completeness -- never re-derived here. Per-VM convenience/dashboard gauge only; NOT the recording rule's input (see bsod_vm_checks_assessed/_total below for that)."
    echo "# TYPE bsod_evidence_completeness_percent gauge"
    echo "# HELP bsod_vm_checks_assessed Per-VM count of checks that reached a verdict (FAIL/WARN/PASS) this collection. Pure passthrough of vm_record.assessed_count -- feeds bsod:fleet_evidence_completeness:ratio's sum()/sum() via alerts/bsod-risk-recording-rules.yaml."
    echo "# TYPE bsod_vm_checks_assessed gauge"
    echo "# HELP bsod_vm_checks_total Per-VM count of checks attempted this collection (assessed + unassessed). Denominator for bsod:fleet_evidence_completeness:ratio."
    echo "# TYPE bsod_vm_checks_total gauge"
    echo "# HELP bsod_vm_risk_tier Per-VM risk tier, always 1 (single active-tier series per VM; the other five tier values are never emitted at 0 for that VM). tier is cnv-win-bsod-audit.sh's own risk_tier() value (PASS|CRITICAL|HIGH|MEDIUM|LOW), EXCEPT this exporter overrides it to UNKNOWN whenever assessed_count==0 for that VM (a tier computed from zero evidence is not a real verdict) -- see the module header's R-27 PHASE 2 TIER VOCABULARY note."
    echo "# TYPE bsod_vm_risk_tier gauge"
    echo "# HELP bsod_vm_finding_count Per-VM count of findings by severity this collection (severity=fail|warn|unknown). fail/warn are pure passthroughs of vm_record.fail_count/warn_count; unknown reuses the same unassessed_count already exported via bsod_vm_checks_total's denominator."
    echo "# TYPE bsod_vm_finding_count gauge"
    # jq emits one TSV line per VM: namespace, name, evidence_completeness,
    # assessed_count, unassessed_count, tier, fail_count, warn_count. total is
    # derived here (assessed + unassessed) rather than re-read from a second
    # audit-script field -- both addends are already exact integers, so no
    # precision is lost the way it would be trying to reverse-derive a count
    # from the ROUNDED evidence_completeness percent. Defensive `// 0`/
    # `// "UNKNOWN"` fallbacks guard a version-mismatched audit script (older
    # cnv-win-bsod-audit.sh without these fields) from breaking `read` below.
    if [ -n "$vms_json" ] && [ "$vms_json" != "null" ]; then
      while IFS=$'\t' read -r _ns _name _pct _assessed _unassessed _tier _fail _warn; do
        [ -z "$_name" ] && continue
        local _total=$(( _assessed + _unassessed ))
        echo "bsod_evidence_completeness_percent{namespace=\"${_ns}\",vm=\"${_name}\"} ${_pct}"
        echo "bsod_vm_checks_assessed{namespace=\"${_ns}\",vm=\"${_name}\"} ${_assessed}"
        echo "bsod_vm_checks_total{namespace=\"${_ns}\",vm=\"${_name}\"} ${_total}"
        # R-27 PHASE 2: zero evidence overrides whatever tier risk_tier()
        # reported -- see module header's TIER VOCABULARY note.
        local _effective_tier="$_tier"
        [ "$_assessed" -eq 0 ] && _effective_tier="UNKNOWN"
        echo "bsod_vm_risk_tier{namespace=\"${_ns}\",vm=\"${_name}\",tier=\"${_effective_tier}\"} 1"
        echo "bsod_vm_finding_count{namespace=\"${_ns}\",vm=\"${_name}\",severity=\"fail\"} ${_fail}"
        echo "bsod_vm_finding_count{namespace=\"${_ns}\",vm=\"${_name}\",severity=\"warn\"} ${_warn}"
        echo "bsod_vm_finding_count{namespace=\"${_ns}\",vm=\"${_name}\",severity=\"unknown\"} ${_unassessed}"
      done < <(printf '%s' "$vms_json" | jq -r '.[] | [.namespace, .name, .evidence_completeness, (.assessed_count // 0), (.unassessed_count // 0), (.tier // "UNKNOWN"), (.fail_count // 0), (.warn_count // 0)] | @tsv')
    fi

    echo "# HELP bsod_evidence_exporter_last_collection_timestamp_seconds Unix time of the most recent collection attempt (success or failure) -- this exporter's own health, not a BSOD-risk signal."
    echo "# TYPE bsod_evidence_exporter_last_collection_timestamp_seconds gauge"
    echo "bsod_evidence_exporter_last_collection_timestamp_seconds $(date -u +%s)"

    echo "# HELP bsod_evidence_exporter_last_collection_success Whether the most recent collection attempt produced valid JSON (1) or not (0)."
    echo "# TYPE bsod_evidence_exporter_last_collection_success gauge"
    echo "bsod_evidence_exporter_last_collection_success $collect_ok"

    echo "# HELP bsod_evidence_exporter_interval_below_recommended Whether EXPORTER_INTERVAL_SECONDS is below the recommended floor for the fleet size observed in the most recent successful collection (1) or not (0). See the module header's INTERVAL-VS-FLEET-SIZE note -- a WARN is also logged when this is 1."
    echo "# TYPE bsod_evidence_exporter_interval_below_recommended gauge"
    echo "bsod_evidence_exporter_interval_below_recommended $interval_below_recommended"
  } > "$tmp"

  mv -f "$tmp" "$METRICS_FILE"
}

# check_interval_floor <total_vms>: sets the global INTERVAL_BELOW_RECOMMENDED
# (0/1) and logs a WARN when EXPORTER_INTERVAL_SECONDS is below the
# recommended floor for the given fleet size. See the module header's
# INTERVAL-VS-FLEET-SIZE note for why this is a soft signal, evaluated only
# after a real collection (total_vms unknown before then), not a hard
# startup check.
INTERVAL_BELOW_RECOMMENDED=0
check_interval_floor() {
  local total_vms="${1:-0}"
  INTERVAL_BELOW_RECOMMENDED=0
  if [ "$total_vms" -ge "$EXPORTER_INTERVAL_FLOOR_VMS_TIER2" ] \
     && [ "$EXPORTER_INTERVAL_SECONDS" -lt "$EXPORTER_INTERVAL_FLOOR_SECONDS_TIER2" ]; then
    log "WARN: total_vms=$total_vms with EXPORTER_INTERVAL_SECONDS=${EXPORTER_INTERVAL_SECONDS}s -- recommend >= ${EXPORTER_INTERVAL_FLOOR_SECONDS_TIER2}s at this fleet size (docs/operator-runbook.md's Fleet Evidence-Completeness Exporter section)"
    INTERVAL_BELOW_RECOMMENDED=1
  elif [ "$total_vms" -ge "$EXPORTER_INTERVAL_FLOOR_VMS_TIER1" ] \
       && [ "$EXPORTER_INTERVAL_SECONDS" -lt "$EXPORTER_INTERVAL_FLOOR_SECONDS_TIER1" ]; then
    log "WARN: total_vms=$total_vms with EXPORTER_INTERVAL_SECONDS=${EXPORTER_INTERVAL_SECONDS}s -- recommend >= ${EXPORTER_INTERVAL_FLOOR_SECONDS_TIER1}s at this fleet size (docs/operator-runbook.md's Fleet Evidence-Completeness Exporter section)"
    INTERVAL_BELOW_RECOMMENDED=1
  fi
}

# collect_once: run the audit across the target scope, parse its JSON, write
# the metrics file. On any failure to produce valid JSON, the per-VM gauges
# are simply omitted this round (Prometheus marks them stale after 5m, which
# is the correct read: "we stopped hearing from this VM", not "it recovered
# to 0%") -- only the exporter's own last_collection_* health gauges always
# reflect the attempt that just happened.
collect_once() {
  local ns_args=()
  if [ -n "$EXPORTER_NAMESPACE" ]; then
    ns_args=(--namespace "$EXPORTER_NAMESPACE")
  else
    ns_args=(--all-namespaces)
  fi

  local raw
  local export_env=()
  [ "$EXPORTER_SKIP_MICROCODE_PROBE" = "1" ] && export_env+=(BSOD_SKIP_MICROCODE_PROBE=1)
  raw=$(env "${export_env[@]}" "$AUDIT_SCRIPT" "${ns_args[@]}" --json 2>/tmp/bsod-fleet-exporter-last-stderr.log)
  # cnv-win-bsod-audit.sh exits 1 whenever any FAIL was found -- that is an
  # expected, common outcome, not a collection failure. Only "did it produce
  # parseable JSON with the summary object this script depends on" gates
  # whether this run's numbers are trusted below.
  #
  # `jq empty` alone is not sufficient here: on EMPTY input it exits 0
  # (there is no invalid JSON to object to), which would have silently
  # treated a zero-byte response -- e.g. AUDIT_SCRIPT crashing before
  # printing anything, or a cluster/RBAC failure the script itself could not
  # recover from -- as a successful collection. The explicit `-n "$raw"`
  # check and `.summary` presence check close that gap.
  if [ -z "$raw" ] || ! printf '%s' "$raw" | jq -e '.summary' >/dev/null 2>&1; then
    log "ERROR: audit script did not produce valid JSON -- see /tmp/bsod-fleet-exporter-last-stderr.log. Omitting per-VM gauges this round."
    write_metrics "" 0
    return 1
  fi

  local vms_json total_vms
  vms_json=$(printf '%s' "$raw" | jq -c '.vms // []')
  total_vms=$(printf '%s' "$raw" | jq -r '.summary.total_vms // 0')

  check_interval_floor "$total_vms"
  write_metrics "$vms_json" 1 "$INTERVAL_BELOW_RECOMMENDED"
  log "collected: total_vms=$total_vms interval_below_recommended=$INTERVAL_BELOW_RECOMMENDED"
  return 0
}

# tests/test_bash_fleet_exporter.sh sources this file to unit-test
# write_metrics()/collect_once() directly (with AUDIT_SCRIPT pointed at a
# fixture stub) without starting the HTTP server or the infinite collection
# loop below.
if [ "${BSOD_EXPORTER_SOURCE_ONLY:-0}" = "1" ]; then
  # `return` is the normal path (this script is meant to be sourced with
  # this flag set); `exit` is a defensive fallback only if someone instead
  # executes it directly with the flag set, where a bare top-level `return`
  # would itself error out. shellcheck can't see that the `exit` is
  # reachable only in that second, less common invocation shape.
  # shellcheck disable=SC2317
  return 0 2>/dev/null || exit 0
fi

# --- Startup ---
# A placeholder file exists BEFORE the HTTP server starts, so a scrape or
# readiness probe during the very first (possibly slow, fleet-wide)
# collection sees a valid, well-formed response rather than racing
# serve-metrics.py's own "file not found" path.
write_metrics "" 0

python3 "$SCRIPT_DIR/lib/serve-metrics.py" --file "$METRICS_FILE" --port "$EXPORTER_PORT" &
SERVER_PID=$!
log "started metrics HTTP server (pid $SERVER_PID) on :$EXPORTER_PORT/metrics"

SHUTTING_DOWN=0
on_term() {
  [ "$SHUTTING_DOWN" -eq 1 ] && return
  SHUTTING_DOWN=1
  log "received termination signal, shutting down"
  kill "$SERVER_PID" 2>/dev/null || true
  exit 0
}
trap on_term TERM INT

log "cnv-bsod-fleet-exporter.sh starting: namespace=${EXPORTER_NAMESPACE:-<all>} interval=${EXPORTER_INTERVAL_SECONDS}s skip_microcode_probe=${EXPORTER_SKIP_MICROCODE_PROBE}"

while true; do
  collect_once || true
  # `sleep` in the foreground so TERM/INT is handled promptly between
  # iterations rather than only after a full sleep completes -- `wait` on a
  # backgrounded sleep lets the trap fire immediately.
  sleep "$EXPORTER_INTERVAL_SECONDS" &
  wait $!
done
