#!/usr/bin/env bash
#
# cnv-mtv-fleet-readiness.sh
# -----------------------------------------------------------------------------
# Run the Windows-BSOD risk audit across EVERY MTV Plan in a namespace
# and roll the results up into a wave-by-wave readiness report suitable for a
# migration steering review.
#
# Delegates each plan to cnv-mtv-plan-gate.sh (same directory), which in turn
# delegates each VM to cnv-win-bsod-audit.sh. This wrapper only
# orchestrates and aggregates -- all gate logic lives in the lower layers.
#
# Usage:
#   ./cnv-mtv-fleet-readiness.sh [plan-namespace] [--csv combined.csv]
#
# Env overrides (mainly for testing / air-gapped review):
#   FLEET_PLAN_DIR  directory of Plan *.json files to use instead of oc
#   BSOD_CHECK_CMD  per-VM checker (passed through to the plan gate)
#   WAVE_KEY        Plan label/annotation key holding the wave id
#
# Requires: oc (logged in) in live mode; the sibling scripts; awk.
# Exit non-zero if ANY wave is BLOCKED.
# -----------------------------------------------------------------------------
# NOTE: -e is intentionally omitted so individual plan gates can fail
# without aborting the fleet readiness report. Results are aggregated per-wave.
set -uo pipefail

PLAN_NS="openshift-mtv"
CSV_OUT=""
STRICT_FLAG=""
# arg parse: first non-flag = namespace
while [ $# -gt 0 ]; do
  case "$1" in
    --csv) CSV_OUT="${2:-}"; shift 2 ;;
    --strict) STRICT_FLAG="--strict"; shift ;;
    -*)    shift ;;
    *)     PLAN_NS="$1"; shift ;;
  esac
done
# Also honor BSOD_STRICT env. N12: must check the VALUE, not merely
# PRESENCE -- see the identical fix/comment in cnv-mtv-plan-gate.sh.
if [ "${BSOD_STRICT:-}" = "true" ] && [ -z "$STRICT_FLAG" ]; then
  STRICT_FLAG="--strict"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_GATE="$SCRIPT_DIR/cnv-mtv-plan-gate.sh"
[ -x "$PLAN_GATE" ] || [ -f "$PLAN_GATE" ] || { echo "missing $PLAN_GATE" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
COMBINED="$WORK/combined.csv"
: > "$COMBINED"
MAP="$WORK/plan-wave.map"   # lines: wave|plan
: > "$MAP"
# Cluster-scope FAIL/WARN counts + raw exit code per plan (see cnv-mtv-plan-gate.sh's
# "Cluster-scope: FAIL=N WARN=N" line). A Plan's own gate can independently print
# "GATE: BLOCKED" over a cluster-scope hard failure (e.g. no auto-detectable
# Windows VMs, AMD Family 1Ah nodes) even when every individual VM PASSes/WARNs --
# that signal lives outside the per-VM CSV rows this script otherwise aggregates,
# so it must be captured here too or a real BLOCKED wave silently reports REVIEW.
CLUSTER_MAP="$WORK/plan-cluster.map"   # lines: plan|cluster_fail|cluster_warn
: > "$CLUSTER_MAP"

echo "=============================================================="
echo " MTV fleet readiness  --  namespace: $PLAN_NS"
echo "=============================================================="

# --- enumerate plans ---------------------------------------------------------
declare -a PLANS
declare -A PLAN_JSON
if [ -n "${FLEET_PLAN_DIR:-}" ]; then
  for f in "$FLEET_PLAN_DIR"/*.json; do
    [ -e "$f" ] || continue
    p="$(basename "$f" .json)"
    PLANS+=("$p"); PLAN_JSON["$p"]="$f"
  done
else
  command -v oc >/dev/null 2>&1 || { echo "oc is required (or set FLEET_PLAN_DIR)" >&2; exit 2; }
  mapfile -t PLANS < <(
    oc get plan.forklift.konveyor.io -n "$PLAN_NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    || oc get plan -n "$PLAN_NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null )
fi

if [ "${#PLANS[@]}" -eq 0 ]; then
  echo "No plans found in namespace $PLAN_NS."; exit 1
fi
echo "Found ${#PLANS[@]} plan(s): ${PLANS[*]}"

# --- run the gate per plan ---------------------------------------------------
for p in "${PLANS[@]}"; do
  pcsv="$WORK/$p.csv"
  plan_exit=0
  if [ -n "${FLEET_PLAN_DIR:-}" ]; then
    log=$(MTV_PLAN_JSON="${PLAN_JSON[$p]}" \
          BSOD_CHECK_CMD="${BSOD_CHECK_CMD:-}" \
          WAVE_KEY="${WAVE_KEY:-}" \
          BSOD_STRICT="${BSOD_STRICT:-}" \
          bash "$PLAN_GATE" "$p" "$PLAN_NS" --csv "$pcsv" $STRICT_FLAG 2>&1) || plan_exit=$?
  else
    log=$(BSOD_CHECK_CMD="${BSOD_CHECK_CMD:-}" \
          WAVE_KEY="${WAVE_KEY:-}" \
          BSOD_STRICT="${BSOD_STRICT:-}" \
          bash "$PLAN_GATE" "$p" "$PLAN_NS" --csv "$pcsv" $STRICT_FLAG 2>&1) || plan_exit=$?
  fi

  # learn the wave this plan resolved to (from the gate's header line)
  wave=$(printf '%s\n' "$log" | sed -n 's/.*Wave: \([^ ]*\).*/\1/p' | head -1)
  [ -z "$wave" ] && wave="$p"
  echo "$wave|$p" >> "$MAP"

  # capture the plan's own cluster-scope FAIL/WARN counts (see comment above
  # CLUSTER_MAP) so they roll into this plan's wave verdict below.
  cluster_fail=$(printf '%s\n' "$log" | sed -n 's/.*Cluster-scope: FAIL=\([0-9][0-9]*\).*/\1/p' | head -1)
  cluster_warn=$(printf '%s\n' "$log" | sed -n 's/.*Cluster-scope:.*WARN=\([0-9][0-9]*\).*/\1/p' | head -1)
  [ -z "$cluster_fail" ] && cluster_fail=0
  [ -z "$cluster_warn" ] && cluster_warn=0
  # Defensive fallback: a plan gate that exited non-zero without printing a
  # recognizable cluster-scope FAIL count (e.g. it crashed before completing)
  # must still block the wave rather than silently rolling up as CLEAR/REVIEW.
  if [ "$plan_exit" -ne 0 ] && [ "$cluster_fail" -eq 0 ] && [ ! -s "$pcsv" ]; then
    echo "WARN: plan '$p' gate exited $plan_exit with no CSV output -- treating as a cluster FAIL" >&2
    cluster_fail=1
  fi
  echo "$p|$cluster_fail|$cluster_warn" >> "$CLUSTER_MAP"

  # append data rows (skip the CSV header line)
  if [ -f "$pcsv" ]; then
    grep -v '^vm,wave,' "$pcsv" >> "$COMBINED" 2>/dev/null || true
  fi
done

# --- aggregate by wave -------------------------------------------------------
# CSV fields are all double-quoted; only the trailing "detail" may contain
# commas, so splitting on the literal sequence ","  is safe for wave ($2)
# and status ($5).
echo
printf '%-10s %-22s %-5s %-5s %-5s %-5s %-6s %-5s %-9s\n' \
  "WAVE" "PLANS" "VMS" "PASS" "WARN" "FAIL" "CFAIL" "PEND" "VERDICT"
printf '%-10s %-22s %-5s %-5s %-5s %-5s %-6s %-5s %-9s\n' \
  "----------" "----------------------" "-----" "-----" "-----" "-----" "------" "-----" "---------"

ANY_BLOCKED=0
T_CFAIL=0
T_CWARN=0
# unique waves, preserving first-seen order
mapfile -t WAVES < <(cut -d'|' -f1 "$MAP" | awk '!seen[$0]++')

for w in "${WAVES[@]}"; do
  # plans in this wave
  plans=$(awk -F'|' -v w="$w" '$1==w{print $2}' "$MAP" | paste -sd',' -)
  pshow="$plans"; [ "${#pshow}" -gt 22 ] && pshow="${pshow:0:19}..."

  # tally statuses for rows whose wave column ($2) == w
  read -r vms pass warn fail pend < <(
    awk -F'","' -v w="$w" '
      $0 ~ /^"/ && $2==w {
        tot++
        if ($5=="PASS") p++
        # UNASSESSED (gate could not evaluate -- missing evidence) rolls into
        # the review bucket, matching cnv-mtv-plan-gate.sh s verdict mapping.
        # It must never land in PASS, and it must not fall through unbucketed:
        # without this branch the per-status columns silently stop summing to
        # the VMS total, hiding unassessed VMs from wave planning entirely.
        else if ($5=="WARN" || $5=="UNASSESSED") wn++
        else if ($5=="FAIL") f++
        else if ($5=="PENDING" || $5=="UNRESOLVED") pe++
        else other++
      }
      END {
        # Fail loud if a status was seen that no branch recognises -- a silently
        # dropped status is how an unassessed VM becomes an invisible one.
        if (other+0 > 0)
          printf "WARN: %d row(s) with unrecognised status in wave %s\n", other, w > "/dev/stderr"
        printf "%d %d %d %d %d\n", tot+0, p+0, wn+0, f+0, pe+0
      }
    ' "$COMBINED" )

  # sum cluster-scope FAIL/WARN across every plan mapped to this wave -- this
  # is the signal cnv-mtv-plan-gate.sh's own "GATE: BLOCKED" verdict can be
  # based on even when every per-VM row is PASS/WARN (see CLUSTER_MAP above).
  read -r cfail cwarn < <(
    awk -F'|' -v w="$w" '
      NR==FNR { if ($1==w) plans[$2]=1; next }
      ($1 in plans) { cf+=$2; cw+=$3 }
      END { printf "%d %d\n", cf+0, cw+0 }
    ' "$MAP" "$CLUSTER_MAP")
  T_CFAIL=$((T_CFAIL + cfail))
  T_CWARN=$((T_CWARN + cwarn))

  if   [ "$fail" -gt 0 ] || [ "$cfail" -gt 0 ]; then verdict="BLOCKED"; ANY_BLOCKED=1
  elif [ "$warn" -gt 0 ] || [ "$pend" -gt 0 ] || [ "$cwarn" -gt 0 ]; then verdict="REVIEW"
  else verdict="CLEAR"; fi

  wshow="$w"; [ "${#wshow}" -gt 10 ] && wshow="${wshow:0:10}"
  printf '%-10s %-22s %-5s %-5s %-5s %-5s %-6s %-5s %-9s\n' \
    "$wshow" "$pshow" "$vms" "$pass" "$warn" "$fail" "$cfail" "$pend" "$verdict"
done

# --- fleet totals ------------------------------------------------------------
# N4: mirror the per-wave block's UNASSESSED/other handling exactly (see the
# comment above it). Without this, an UNASSESSED row contributes to $tot but
# to none of PASS/WARN/FAIL/PEND, so an all-UNASSESSED fleet (e.g. every VM
# still stopped, no VMI to assess) summed to all-zero WARN/FAIL/PEND and the
# final verdict below fell through to "FLEET GATE: CLEAR" -- migration-ready
# on a fleet that was never actually assessed.
read -r T_VMS T_PASS T_WARN T_FAIL T_PEND T_OTHER < <(
  awk -F'","' '
    $0 ~ /^"/ {
      tot++
      if ($5=="PASS") p++
      else if ($5=="WARN" || $5=="UNASSESSED") wn++
      else if ($5=="FAIL") f++
      else if ($5=="PENDING" || $5=="UNRESOLVED") pe++
      else other++
    }
    END {
      if (other+0 > 0)
        printf "WARN: %d row(s) with unrecognised status in fleet totals\n", other > "/dev/stderr"
      printf "%d %d %d %d %d %d\n", tot+0, p+0, wn+0, f+0, pe+0, other+0
    }
  ' "$COMBINED" )

echo
echo "Fleet totals: VMs=$T_VMS  PASS=$T_PASS  WARN=$T_WARN  FAIL=$T_FAIL  PENDING=$T_PEND"
echo "Fleet cluster-scope totals: FAIL=$T_CFAIL  WARN=$T_CWARN"

# --- optional combined CSV ---------------------------------------------------
if [ -n "$CSV_OUT" ]; then
  { echo "vm,wave,target_namespace,migration_type,status,detail"; cat "$COMBINED"; } > "$CSV_OUT"
  echo "Combined CSV written: $CSV_OUT"
fi

# --- fleet verdict + exit ----------------------------------------------------
echo
if [ "$ANY_BLOCKED" -eq 1 ]; then
  echo "FLEET GATE: BLOCKED. One or more waves have failing VMs or cluster-scope FAILs -- do not proceed."
  exit 1
elif [ "$T_WARN" -gt 0 ] || [ "$T_PEND" -gt 0 ] || [ "$T_CWARN" -gt 0 ] || [ "${T_OTHER:-0}" -gt 0 ]; then
  echo "FLEET GATE: REVIEW. No hard failures; warnings/pending/unassessed items need sign-off."
  exit 0
else
  echo "FLEET GATE: CLEAR. All waves ready."
  exit 0
fi
