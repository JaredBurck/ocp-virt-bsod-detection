#!/usr/bin/env bash
#
# cnv-mtv-plan-gate.sh
# -----------------------------------------------------------------------------
# Run the Windows-BSOD risk audit across every VM in an MTV
# (Migration Toolkit for Virtualization / forklift) Plan, and print a
# per-VM PASS / WARN / FAIL / PENDING summary mapped to migration waves.
#
# Delegates the actual per-VM checks to cnv-win-bsod-audit.sh
# (expected in the same directory) so the gate logic stays in one place.
#
# VM lookups use .spec.vms[].targetName when the Plan renames a VM on
# import, falling back to .name otherwise -- looking up only by the source
# name would leave a renamed VM permanently misreported as PENDING even
# after a successful import. The summary table/CSV show the resolved
# target-namespace name (the actual in-cluster resource and the join key
# consumed by cnv-mtv-fleet-readiness.sh / analyze.py --wave-map), with a
# "source -> target" label only when a rename occurred.
#
# Wave model: MTV Plans have no native "wave" field. This wrapper treats the
# Plan as the wave unit by default, and will instead use a wave label/annotation
# on the Plan if present (override the key with WAVE_KEY).
#
# Usage:
#   ./cnv-mtv-plan-gate.sh <plan-name> [plan-namespace]
#   ./cnv-mtv-plan-gate.sh <plan-name> [plan-namespace] --csv report.csv
#
# Env overrides (mainly for testing / air-gapped review):
#   MTV_PLAN_JSON   path to a Plan JSON file to use instead of calling oc
#   BSOD_CHECK_CMD  command to run per VM (default: ./cnv-win-bsod-audit.sh)
#   WAVE_KEY        label/annotation key on the Plan holding the wave id
#
# Requires: oc (logged in), jq.  Exit non-zero if any VM is FAIL.
# -----------------------------------------------------------------------------
# NOTE: -e is intentionally omitted so individual VM checks can fail
# without aborting the full plan gate. Results are classified per-VM.
set -uo pipefail

PLAN="${1:?usage: $0 <plan-name> [plan-namespace] [--csv file] [--json file] [--strict]}"
PLAN_NS="${2:-openshift-mtv}"
CSV_OUT=""
JSON_OUT=""
STRICT_FLAG=""
# crude flag parse for --csv / --json / --strict
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --csv) CSV_OUT="${2:-}"; shift 2 ;;
    --json) JSON_OUT="${2:-}"; shift 2 ;;
    --strict) STRICT_FLAG="--strict"; shift ;;
    *) shift ;;
  esac
done
# Also honor BSOD_STRICT env (set by fleet-readiness or operator). N12:
# must check the VALUE, not merely PRESENCE -- `[ -n "${BSOD_STRICT:-}" ]`
# is true for BSOD_STRICT=false too, silently promoting warnings to hard
# failures on a value that explicitly asked to opt OUT of --strict.
if [ "${BSOD_STRICT:-}" = "true" ] && [ -z "$STRICT_FLAG" ]; then
  STRICT_FLAG="--strict"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BSOD_CHECK_CMD="${BSOD_CHECK_CMD:-$SCRIPT_DIR/cnv-win-bsod-audit.sh}"
WAVE_KEY="${WAVE_KEY:-}"

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

strip_ansi() { sed -r 's/\x1b\[[0-9;]*m//g'; }

# --- fetch the Plan ----------------------------------------------------------
if [ -n "${MTV_PLAN_JSON:-}" ]; then
  plan=$(cat "$MTV_PLAN_JSON") || { echo "cannot read MTV_PLAN_JSON=$MTV_PLAN_JSON" >&2; exit 2; }
else
  command -v oc >/dev/null 2>&1 || { echo "oc is required (or set MTV_PLAN_JSON)" >&2; exit 2; }
  plan=$(oc get plan.forklift.konveyor.io "$PLAN" -n "$PLAN_NS" -o json 2>/dev/null) \
    || plan=$(oc get plan "$PLAN" -n "$PLAN_NS" -o json 2>/dev/null) \
    || { echo "could not fetch Plan '$PLAN' in namespace '$PLAN_NS'" >&2; exit 1; }
fi

TARGET_NS=$(echo "$plan" | jq -r '.spec.targetNamespace // "unknown"')
WARM=$(echo "$plan"      | jq -r 'if .spec.warm == true then "warm" else "cold" end')

# Wave: from label/annotation if WAVE_KEY given and present, else the plan name.
WAVE="$PLAN"
if [ -n "$WAVE_KEY" ]; then
  w=$(echo "$plan" | jq -r --arg k "$WAVE_KEY" '
    (.metadata.labels[$k] // .metadata.annotations[$k] // empty)')
  [ -n "$w" ] && WAVE="$w"
fi

echo "=============================================================="
echo " MTV Plan gate: $PLAN  (ns: $PLAN_NS)"
echo " Target namespace: $TARGET_NS   Migration type: $WARM   Wave: $WAVE"
echo "=============================================================="

# --- R-23: warm a cluster-scope cache shared by every per-VM invocation -------
# Each per-VM run below is a FRESH audit process that would otherwise re-fetch
# the worker node list, Windows templates, cluster instancetypes and cluster
# preferences -- identical for every VM in the wave. At 500-1000 VM scale that
# is thousands of redundant apiserver calls on the migration-blocking path.
#
# The cache is per-run and lives in $WORK (already trap-cleaned), so it cannot
# outlive the gate or be reused across waves against a changed cluster.
# Namespace/status-bearing fetches are NOT cached -- see _OC_CACHEABLE in
# cnv-win-bsod-audit.sh for why VMI status must stay live.
# This script has no pre-existing scratch dir, so create and trap-clean one.
BSOD_CLUSTER_CACHE_DIR="$(mktemp -d)"
export BSOD_CLUSTER_CACHE_DIR
trap 'rm -rf "$BSOD_CLUSTER_CACHE_DIR"' EXIT

# --- print cluster-scope checks once before per-VM loop ----------------------
CLUSTER_FAIL=0
CLUSTER_WARN=0
CLUSTER_UNKNOWN=0
if [ -z "${MTV_PLAN_JSON:-}" ]; then
  cluster_out=$("$BSOD_CHECK_CMD" $STRICT_FLAG --cluster-scope-only "$TARGET_NS" 2>&1)
  cluster_rc=$?
  printf '%s\n' "$cluster_out"
  CLUSTER_FAIL=$(printf '%s\n' "$cluster_out" | grep -c '\[FAIL\]' || true)
  CLUSTER_WARN=$(printf '%s\n' "$cluster_out" | grep -c '\[WARN\]' || true)
  CLUSTER_UNKNOWN=$(printf '%s\n' "$cluster_out" | grep -c '\[UNKN\]' || true)
  # Prefer explicit FAIL lines; fall back to non-zero exit from audit
  if [ "$cluster_rc" -ne 0 ] && [ "${CLUSTER_FAIL:-0}" -eq 0 ]; then
    CLUSTER_FAIL=1
  fi
fi

# --- iterate plan VMs --------------------------------------------------------
# VM_NAMES holds the *source* name (as MTV/Forklift discovered it on the
# source provider) for display; VM_TARGET_NAMES holds the name the VM will
# actually be created as in TARGET_NS -- .spec.vms[].targetName when the plan
# renames the VM on import, falling back to .name when it doesn't. Looking up
# `oc get vm "$name"` using only the source name (as this script previously
# did) leaves a renamed VM stuck reporting PENDING/"not yet imported" forever
# after a successful import, since the resource only exists under targetName.
mapfile -t VM_NAMES        < <(echo "$plan" | jq -r '.spec.vms[]? | (.name // "")')
mapfile -t VM_TARGET_NAMES < <(echo "$plan" | jq -r '.spec.vms[]? | (.targetName // .name // "")')
mapfile -t VM_IDS          < <(echo "$plan" | jq -r '.spec.vms[]? | (.id   // "")')

if [ "${#VM_NAMES[@]}" -eq 0 ]; then
  echo "Plan lists no VMs (.spec.vms is empty)."; exit 1
fi

# results arrays. R_VM always holds the canonical *target*-namespace
# resource name (never the cosmetic "source -> target" label) since it is
# both what cnv-win-bsod-audit.sh/oc actually looked up and the join key
# consumed downstream (--csv output -> cnv-mtv-fleet-readiness.sh's combined
# CSV -> analyze.py --wave-map, which matches on the VM's real in-cluster
# name). R_SOURCE_VM tracks the original source-provider name separately,
# used only to build the "source -> target" label at print time when a
# rename actually happened.
declare -a R_VM R_SOURCE_VM R_STATUS R_DETAIL
FAIL_TOTAL=0; WARN_TOTAL=0; PEND_TOTAL=0; PASS_TOTAL=0; UNKNOWN_TOTAL=0

for i in "${!VM_NAMES[@]}"; do
  name="${VM_NAMES[$i]}"
  target_name="${VM_TARGET_NAMES[$i]:-$name}"
  id="${VM_IDS[$i]}"

  if [ -z "$target_name" ]; then
    R_VM+=("(id:${id:-?})"); R_SOURCE_VM+=(""); R_STATUS+=("UNRESOLVED")
    R_DETAIL+=("plan VM has only an id; supply target name to check")
    PEND_TOTAL=$((PEND_TOTAL+1)); continue
  fi

  # Does the target VirtualMachine exist yet? Always look up by targetName
  # (falls back to name when the plan doesn't rename) -- looking up by the
  # source name alone would never find a renamed VM even after a successful
  # import, permanently misreporting it as PENDING.
  exists="no"
  if [ -z "${MTV_PLAN_JSON:-}" ]; then
    if oc get vm "$target_name" -n "$TARGET_NS" >/dev/null 2>&1; then exists="yes"; fi
  else
    # offline/test mode: treat presence of stub command as "exists"
    exists="yes"
  fi

  if [ "$exists" != "yes" ]; then
    R_VM+=("$target_name"); R_SOURCE_VM+=("$name"); R_STATUS+=("PENDING")
    R_DETAIL+=("not yet imported -- run guest-side check on source VM")
    PEND_TOTAL=$((PEND_TOTAL+1)); continue
  fi

  # Run the per-VM gate with --per-vm-only to exclude cluster-scope
  # output from verdict counting (cluster checks printed once above).
  out=$("$BSOD_CHECK_CMD" $STRICT_FLAG --per-vm-only "$TARGET_NS" "$target_name" 2>&1 | strip_ansi)
  fails=$(printf '%s\n' "$out" | grep -c '\[FAIL\]')
  warns=$(printf '%s\n' "$out" | grep -c '\[WARN\]')
  # [UNKN] = a gate could not be evaluated (missing evidence). This MUST be
  # counted: classifying a VM by "no FAIL and no WARN" would otherwise mark an
  # entirely unassessed VM as PASS -- a brand-new false all-clear introduced by
  # the very mechanism meant to eliminate them. Never let this fall through.
  unknowns=$(printf '%s\n' "$out" | grep -c '\[UNKN\]')

  if [ "$fails" -gt 0 ]; then
    detail=$(printf '%s\n' "$out" | grep -m1 '\[FAIL\]' | sed 's/.*\[FAIL\] //')
    R_VM+=("$target_name"); R_SOURCE_VM+=("$name"); R_STATUS+=("FAIL"); R_DETAIL+=("$detail")
    FAIL_TOTAL=$((FAIL_TOTAL+1))
  elif [ "$warns" -gt 0 ]; then
    detail=$(printf '%s\n' "$out" | grep -m1 '\[WARN\]' | sed 's/.*\[WARN\] //')
    R_VM+=("$target_name"); R_SOURCE_VM+=("$name"); R_STATUS+=("WARN"); R_DETAIL+=("$detail")
    WARN_TOTAL=$((WARN_TOTAL+1))
  elif [ "$unknowns" -gt 0 ]; then
    detail=$(printf '%s\n' "$out" | grep -m1 '\[UNKN\]' | sed 's/.*\[UNKN\] //')
    R_VM+=("$target_name"); R_SOURCE_VM+=("$name"); R_STATUS+=("UNASSESSED"); R_DETAIL+=("$detail")
    UNKNOWN_TOTAL=$((UNKNOWN_TOTAL+1))
  else
    R_VM+=("$target_name"); R_SOURCE_VM+=("$name"); R_STATUS+=("PASS"); R_DETAIL+=("all gates clear")
    PASS_TOTAL=$((PASS_TOTAL+1))
  fi
done

# --- summary table -----------------------------------------------------------
printf '\n%-30s %-6s %-10s %s\n' "VM" "WAVE" "STATUS" "TOP FINDING"
printf '%-30s %-6s %-10s %s\n' "------------------------------" "------" "----------" "-----------"
for i in "${!R_VM[@]}"; do
  vm="${R_VM[$i]}"
  src="${R_SOURCE_VM[$i]:-}"
  # Only show "source -> target" when the plan actually renamed the VM;
  # keeps the common (no-rename) case exactly as before.
  if [ -n "$src" ] && [ "$src" != "$vm" ]; then
    vm="$src -> $vm"
  fi
  [ "${#vm}" -gt 30 ] && vm="${vm:0:27}..."
  wv="$WAVE";      [ "${#wv}" -gt 6  ] && wv="${wv:0:6}"
  det="${R_DETAIL[$i]}"; [ "${#det}" -gt 60 ] && det="${det:0:57}..."
  printf '%-30s %-6s %-10s %s\n' "$vm" "$wv" "${R_STATUS[$i]}" "$det"
done

echo
echo "Totals: PASS=$PASS_TOTAL  WARN=$WARN_TOTAL  UNASSESSED=$UNKNOWN_TOTAL  FAIL=$FAIL_TOTAL  PENDING=$PEND_TOTAL"
if [ "${CLUSTER_FAIL:-0}" -gt 0 ] || [ "${CLUSTER_WARN:-0}" -gt 0 ] || [ "${CLUSTER_UNKNOWN:-0}" -gt 0 ]; then
  echo "Cluster-scope: FAIL=$CLUSTER_FAIL  WARN=$CLUSTER_WARN  UNASSESSED=$CLUSTER_UNKNOWN"
fi

# --- optional CSV ------------------------------------------------------------
if [ -n "$CSV_OUT" ]; then
  {
    echo "vm,wave,target_namespace,migration_type,status,detail"
    for i in "${!R_VM[@]}"; do
      d=$(printf '%s' "${R_DETAIL[$i]}" | sed 's/"/""/g')
      printf '"%s","%s","%s","%s","%s","%s"\n' \
        "${R_VM[$i]}" "$WAVE" "$TARGET_NS" "$WARM" "${R_STATUS[$i]}" "$d"
    done
  } > "$CSV_OUT"
  echo "CSV written: $CSV_OUT"
fi

# --- optional JSON (for Tekton Results / pipeline integration) ---------------
if [ -n "$JSON_OUT" ]; then
  vm_json="["
  for i in "${!R_VM[@]}"; do
    [ "$i" -gt 0 ] && vm_json+=","
    vm_json+=$(jq -n \
      --arg vm "${R_VM[$i]}" \
      --arg src "${R_SOURCE_VM[$i]:-}" \
      --arg status "${R_STATUS[$i]}" \
      --arg detail "${R_DETAIL[$i]}" \
      '{vm: $vm, source_name: (if $src != "" and $src != $vm then $src else null end), status: $status, detail: $detail}')
  done
  vm_json+="]"

  verdict="PASS"
  if [ "$FAIL_TOTAL" -gt 0 ] || [ "${CLUSTER_FAIL:-0}" -gt 0 ]; then
    verdict="FAIL"
  elif [ "$WARN_TOTAL" -gt 0 ] || [ "$PEND_TOTAL" -gt 0 ] || [ "${CLUSTER_WARN:-0}" -gt 0 ] \
       || [ "$UNKNOWN_TOTAL" -gt 0 ] || [ "${CLUSTER_UNKNOWN:-0}" -gt 0 ]; then
    # UNASSESSED maps to WARN, never PASS -- an unevaluated VM is not a cleared VM.
    verdict="WARN"
  fi

  jq -n \
    --arg plan "$PLAN" \
    --arg plan_ns "$PLAN_NS" \
    --arg target_ns "$TARGET_NS" \
    --arg wave "$WAVE" \
    --arg migration_type "$WARM" \
    --arg verdict "$verdict" \
    --argjson pass "$PASS_TOTAL" \
    --argjson warn "$WARN_TOTAL" \
    --argjson fail "$FAIL_TOTAL" \
    --argjson pending "$PEND_TOTAL" \
    --argjson unassessed "$UNKNOWN_TOTAL" \
    --argjson cluster_unassessed "${CLUSTER_UNKNOWN:-0}" \
    --argjson cluster_fail "${CLUSTER_FAIL:-0}" \
    --argjson cluster_warn "${CLUSTER_WARN:-0}" \
    --argjson vms "$vm_json" \
    '{
      plan: $plan,
      plan_namespace: $plan_ns,
      target_namespace: $target_ns,
      wave: $wave,
      migration_type: $migration_type,
      verdict: $verdict,
      totals: {pass: $pass, warn: $warn, unassessed: $unassessed, fail: $fail, pending: $pending, cluster_fail: $cluster_fail, cluster_warn: $cluster_warn, cluster_unassessed: $cluster_unassessed},
      vms: $vms
    }' > "$JSON_OUT"
  echo "JSON written: $JSON_OUT"
fi

# --- gate exit code ----------------------------------------------------------
if [ "$FAIL_TOTAL" -gt 0 ] || [ "${CLUSTER_FAIL:-0}" -gt 0 ]; then
  echo "GATE: BLOCKED ($FAIL_TOTAL VM FAIL(s), $CLUSTER_FAIL cluster FAIL(s)). Resolve before migrating this wave."
  exit 1
elif [ "$WARN_TOTAL" -gt 0 ] || [ "$PEND_TOTAL" -gt 0 ] || [ "${CLUSTER_WARN:-0}" -gt 0 ] \
     || [ "$UNKNOWN_TOTAL" -gt 0 ] || [ "${CLUSTER_UNKNOWN:-0}" -gt 0 ]; then
  echo "GATE: REVIEW (warnings, unassessed, or pending VMs). No hard failures."
  [ "$UNKNOWN_TOTAL" -gt 0 ] && echo "  $UNKNOWN_TOTAL VM(s) UNASSESSED -- evidence missing, NOT cleared."
  exit 0
else
  echo "GATE: CLEAR. All checkable VMs passed."
  exit 0
fi
