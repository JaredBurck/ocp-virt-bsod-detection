#!/usr/bin/env bash
#
# cnv-win-bsod-audit.sh
# -----------------------------------------------------------------------------
# Windows VM BSOD risk audit for OpenShift Virtualization. Checks cluster-side
# VM configuration against BSOD signatures documented in Red Hat KCS:
#   - 7141237  List of known Windows BSOD issues (OpenShift Virt / RHEL KVM)
#   - 7141291  [Master] Windows VMs failing with BSOD  (virtio-win 1.9.57 baseline)
#   - 7129390  Recommendations when investigating Windows BSOD issues (routing)
#   - 7128506  How to collect information from Windows Guests (evidence)
#   - 263043   RHEV + RDP virtio NIC BSOD (qemu-log signature technique)
#
# This script checks the CLUSTER-SIDE config it can see. The guest-side driver
# version (virtio-win >= 1.9.57) must be confirmed INSIDE Windows -- see the
# companion script collect-windows-guest-info.ps1.
#
# Usage:  ./cnv-win-bsod-audit.sh [OPTIONS] <namespace> [vm-name]
#         ./cnv-win-bsod-audit.sh --all-namespaces [OPTIONS]
# Requires: oc (logged in), jq
# -----------------------------------------------------------------------------
# NOTE: -e is intentionally omitted so individual gate checks can fail
# without aborting the full audit. Failures are tracked via FINDINGS counter.
set -uo pipefail

# --- Gate-to-stop-code mapping (drives --stop-code filtering and --json output) ---
declare -A GATE_STOP_CODES=(
  [1]="0x7B"
  [2]="0x7B"
  [3]="0xD1"
  [4]="0x101,0x9C"
  [5]=""
  [6]=""
  [7]="0x20001"
  [8]="0x4E"
  [9]="0x5D"
  [10]="0x1A"
  [11]="0x1A,0x7A,0x50,0xEF"
  [12]="0x101"
  [13]=""
  [14]=""
  [15]="0x1A,0x7B,0x20001"
  [16]="0xD1"
  [17]="0x20001,0x7B"
  [18]="0x1A"
  [19]="0x20001,0x7B,0x5D"
  # Master remediation plan Phase 4: Gate 21 checks whether a virtio-win
  # driver source was EVER attached for a virtio/scsi-bus boot disk --
  # distinct from Gate 15 (grades the version of an ALREADY guest-confirmed
  # driver) and Gate 1 (grades the boot disk's bus choice itself).
  [21]="0x7B"
  # Gate 20 (alert coverage) is deliberately stop-code-agnostic: it reports
  # which alerts are blind, not which BSOD a VM is at risk of. Restricting it
  # to a stop-code list would hide the coverage gap during exactly the targeted
  # investigations where knowing an alert never fires matters most.
  # N11: "" here reads as "no stop codes map to this gate", which
  # gate_enabled()'s [ -z "$codes" ] check treats as DISABLED under
  # --stop-code -- the exact opposite of "always on". "*" is gate_enabled()'s
  # dedicated always-on sentinel (checked before the empty-string branch).
  [20]="*"
)

# Windows-VM detection contract (see CLAUDE.md "Windows-VM Detection"). Defined
# once here because two call sites in this file need it -- the per-VM loop and
# Gate 20's alert-coverage count. Those must agree by construction: if Gate 20
# counted a different VM population than the audit itself, its "N of M Windows
# VMs are invisible to alerts" figure would be measuring the wrong M.
# Structured OS metadata first; the name heuristic is a fallback only.
_WIN_VM_JQ_SELECT='select(
    (.spec.template.metadata.annotations["vm.kubevirt.io/os"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
    or (.spec.template.metadata.labels["vm.kubevirt.io/template"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
    or (.metadata.labels["vm.kubevirt.io/template"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
    or (.metadata.labels["vm.kubevirt.io/os"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
    or (.spec.template.spec.domain.features.hyperv != null)
    or (.metadata.name | test("(^|[^a-z])win(dows|web|sql|app|dc|ad|rdp|rds|srv|term|fs|print|host|share|dns|dhcp|xp)?([^a-z]|[0-9]|$)";"i"))
  )'

ALL_VMS=0
VM=""
NS=""
PER_VM_ONLY=0
CLUSTER_SCOPE_ONLY=0
STRICT=0
FAIL_ON_UNKNOWN=0
ALL_NAMESPACES=0
declare -a NAMESPACES=()
STOP_CODES=""
JSON_MODE=""
LABEL_SELECTOR=""
OUTPUT_DIR=""
VERBOSE=0
SUMMARY_ONLY=0
NO_COLOR_FLAG=0
GATE7_ADVISORY_SHOWN=0
SUGGEST_ANNOTATE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all-vms) ALL_VMS=1; shift ;;
    --per-vm-only) PER_VM_ONLY=1; shift ;;
    --cluster-scope-only) CLUSTER_SCOPE_ONLY=1; shift ;;
    --strict) STRICT=1; shift ;;
    --fail-on-unknown) FAIL_ON_UNKNOWN=1; shift ;;
    --all-namespaces|-A) ALL_NAMESPACES=1; shift ;;
    --namespace|-n) NAMESPACES+=("$2"); shift 2 ;;
    --stop-code) STOP_CODES="$2"; shift 2 ;;
    --json) JSON_MODE="doc"; shift ;;
    --json=ndjson) JSON_MODE="ndjson"; shift ;;
    --selector|-l) LABEL_SELECTOR="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    --no-color) NO_COLOR_FLAG=1; shift ;;
    --summary-only) SUMMARY_ONLY=1; shift ;;
    --suggest-annotate) SUGGEST_ANNOTATE=1; shift ;;
    --help|-h)
      cat <<'EOF'
Usage: cnv-win-bsod-audit.sh [OPTIONS] [<namespace>] [vm-name]

Namespace scope:
  <namespace>             Audit Windows VMs in a single namespace (positional)
  --namespace|-n <ns>     Specify namespace(s); repeatable for multiple
  --all-namespaces|-A     Audit all namespaces containing VMs

Filtering:
  --all-vms               Check all VMs (default: Windows VMs only)
  --stop-code <codes>     Only run gates relevant to these stop codes (comma-separated hex, e.g. 0x1A,0x4E)
  --selector|-l <sel>     Label selector passed to oc get vm (e.g. app=myapp)
  vm-name                 Target a specific VM regardless of OS hint

Output:
  --json                  Emit single JSON document (suppress ANSI)
  --json=ndjson           Emit one JSON object per finding (streaming)
  --output-dir <path>     Write per-namespace/per-VM report files
  --summary-only          Print executive summary + per-VM verdict table only
  --no-color              Disable ANSI color output (also honors NO_COLOR env)
  --verbose               Show skipped gates when --stop-code is active
  --suggest-annotate      Gate 20 dry-run: for every VM it finds INVISIBLE to
                          annotation-dependent alerts, print the exact
                          `oc annotate vm ...` command that would close the
                          gap. Prints only -- never executes anything, per
                          this framework's no-autonomous-mutation policy.
                          The suggested value is best-effort (derived from
                          the VM's own vm.kubevirt.io/os or
                          vm.kubevirt.io/template label when present, else a
                          generic "windows" flagged for manual verification)
                          -- always confirm it matches the actual guest OS
                          before running it.

Mode:
  --per-vm-only           Suppress cluster-scope output (used by plan gate)
  --cluster-scope-only    Print only cluster-scope checks, skip per-VM loop
  --strict                Promote migration-critical warnings to hard failures
  --fail-on-unknown       Exit 1 if ANY check could not be evaluated (UNKNOWN).
                          Off by default: UNKNOWN means "not assessed", not
                          "failed", and exit 0 has always meant "no confirmed
                          failures" -- never "migration-safe". Intended for
                          UNATTENDED gates (e.g. the Tekton PreHook Job) where
                          no human reads the UNKNOWN count. Note --strict does
                          NOT imply this: --strict promotes WARN, not UNKNOWN.

Environment:
  BSOD_SKIP_MICROCODE_PROBE=1   Skip Gate 8's node microcode probe.
  BSOD_SKIP_PROM_QUERY=1        Skip Gate 11's storage-latency query. The gate
                                then reports UNASSESSED rather than a pass.
  BSOD_PROM_TIMEOUT=<seconds>   Per-query timeout for Gate 11 (default: 20).
  BSOD_GUEST_EVIDENCE_DIR=<dir> Guest artifacts for gates 15/16
                                (default: ./bsod-qga-collect)

PRIVILEGE NOTE: this audit is read-only EXCEPT Gate 8, which runs
'oc debug node/<name>' to read the CPU microcode revision. That creates a
short-lived PRIVILEGED pod on each AMD Family 1Ah node (no such API/metric
exists for microcode). Set BSOD_SKIP_MICROCODE_PROBE=1 to disable it -- the
gate then reports UNASSESSED rather than a pass.

Gate 11 additionally makes a READ-ONLY HTTPS query to the in-cluster
thanos-querier route for storage latency, authenticated with your own token
and verified against the cluster's ingress CA (never with certificate checking
disabled). It reads the bsod:vmi_disk_latency:worst_1h recording rule where
deployed and falls back to the raw KubeVirt storage counters otherwise. Set
BSOD_SKIP_PROM_QUERY=1 to disable it; the gate then reports UNASSESSED.
Every other gate uses only 'get'/'list' and needs no elevated permission.
EOF
      exit 0
      ;;
    *)
      if [ -z "$NS" ]; then NS="$1"
      elif [ -z "$VM" ]; then VM="$1"
      else echo "Unknown argument: $1"; exit 2
      fi
      shift
      ;;
  esac
done

# Color detection: --no-color flag, NO_COLOR env (no-color.org), non-interactive TTY, JSON mode
USE_COLOR=1
if [ "$NO_COLOR_FLAG" -eq 1 ] || [ -n "${NO_COLOR:-}" ] || [ "$JSON_MODE" != "" ]; then
  USE_COLOR=0
elif ! [ -t 1 ]; then
  USE_COLOR=0
fi

# Resolve namespace list: --all-namespaces > --namespace repeats > positional NS
if [ "$ALL_NAMESPACES" -eq 1 ]; then
  : # namespaces resolved after oc/jq checks below
elif [ "${#NAMESPACES[@]}" -gt 0 ]; then
  : # explicit list provided
elif [ -n "$NS" ]; then
  NAMESPACES=("$NS")
else
  if [ "$ALL_NAMESPACES" -eq 0 ]; then
    echo "Usage: $0 [--all-namespaces | --namespace <ns> | <namespace>] [vm-name]"; exit 2
  fi
fi

# Load thresholds from shared config (single source of truth).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_CONFIG="$SCRIPT_DIR/../shared/virtio-win-thresholds.json"
CONTAINER_CONFIG="/usr/share/bsod-detection/shared/virtio-win-thresholds.json"

THRESHOLD_FILE=""
if [ -f "$SHARED_CONFIG" ] && command -v jq >/dev/null 2>&1; then
  THRESHOLD_FILE="$SHARED_CONFIG"
elif [ -f "$CONTAINER_CONFIG" ] && command -v jq >/dev/null 2>&1; then
  THRESHOLD_FILE="$CONTAINER_CONFIG"
fi

# N-06 (Wave 7, R-47): guest-OS-support axis, orthogonal to the host-stream
# thresholds above. See evaluate_guest_os_driver_compatibility in
# scripts/lib/driver-verdict.sh and shared/virtio-win-guest-os-support.json.
SHARED_OS_SUPPORT_CONFIG="$SCRIPT_DIR/../shared/virtio-win-guest-os-support.json"
CONTAINER_OS_SUPPORT_CONFIG="/usr/share/bsod-detection/shared/virtio-win-guest-os-support.json"
OS_SUPPORT_FILE=""
if [ -f "$SHARED_OS_SUPPORT_CONFIG" ] && command -v jq >/dev/null 2>&1; then
  OS_SUPPORT_FILE="$SHARED_OS_SUPPORT_CONFIG"
elif [ -f "$CONTAINER_OS_SUPPORT_CONFIG" ] && command -v jq >/dev/null 2>&1; then
  OS_SUPPORT_FILE="$CONTAINER_OS_SUPPORT_CONFIG"
fi

# R-12 (v0.19.0 unified review U-11): the required Hyper-V feature SET, from
# the same shared/template-baseline.json that bsod_template_checks.py consumes.
# Gates 17/19 previously tested only `hyperv == null` -- a presence check -- so
# a template or preference declaring nothing but `{relaxed: true}` passed bash
# while Python WARNed on the five missing required features. Criticality, not
# presence: synictimer/vpindex/synic are the timer enlightenments tied to
# CLOCK_WATCHDOG_TIMEOUT (0x101) on live migration.
BASELINE_CONFIG="$SCRIPT_DIR/../shared/template-baseline.json"
BASELINE_CONTAINER="/usr/share/bsod-detection/shared/template-baseline.json"
REQUIRED_HYPERV_JSON='["relaxed","vapic","spinlocks","vpindex","synic","synictimer"]'
for _bl in "$BASELINE_CONFIG" "$BASELINE_CONTAINER"; do
  if [ -f "$_bl" ] && command -v jq >/dev/null 2>&1; then
    _bl_val=$(jq -c '.required_hyperv_features // empty' "$_bl" 2>/dev/null)
    [ -n "$_bl_val" ] && REQUIRED_HYPERV_JSON="$_bl_val"
    break
  fi
done

THRESHOLDS_JSON=""
if [ -n "$THRESHOLD_FILE" ]; then
  THRESHOLDS_JSON=$(cat "$THRESHOLD_FILE")
  DRIVER_BASELINE=$(echo "$THRESHOLDS_JSON" | jq -r '.remediation_baseline')
  TOOLING_FLOOR=$(echo "$THRESHOLDS_JSON" | jq -r '.tooling_floor')
  MULTIQUEUE_FIX_BASELINE=$(echo "$THRESHOLDS_JSON" | jq -r '.multiqueue_fix_baseline // "1.9.53"')
else
  DRIVER_BASELINE="1.9.57"
  TOOLING_FLOOR="1.9.41"
  MULTIQUEUE_FIX_BASELINE="1.9.53"
fi

# Stream-aware threshold detection: map OCP version to RHEL stream for
# per-stream fail/warn gates (consistent with Python insights-rules layer).
OCP_VER=""
STREAM=""
STREAM_FAIL=""
STREAM_WARN=""
STREAM_MAX=""
STREAM_NOTE=""
if command -v oc >/dev/null 2>&1; then
  OCP_VER=$(oc get clusterversion version -o jsonpath='{.status.desired.version}' 2>/dev/null | cut -d. -f1-2)
fi
if [ -n "$OCP_VER" ] && [ -n "$THRESHOLD_FILE" ]; then
  STREAM=$(jq -r --arg v "$OCP_VER" \
    '.streams | to_entries[] | select(.value.ocp_versions | index($v)) | .key' \
    "$THRESHOLD_FILE" 2>/dev/null)
  if [ -n "$STREAM" ]; then
    STREAM_FAIL=$(jq -r --arg s "$STREAM" '.streams[$s].fail // empty' "$THRESHOLD_FILE")
    STREAM_WARN=$(jq -r --arg s "$STREAM" '.streams[$s].warn // empty' "$THRESHOLD_FILE")
    STREAM_MAX=$(jq -r --arg s "$STREAM" '.streams[$s].max // empty' "$THRESHOLD_FILE")
    STREAM_NOTE=$(jq -r --arg s "$STREAM" '.streams[$s].note // empty' "$THRESHOLD_FILE")
  fi
fi

# Source the shared driver verdict functions (single source of truth for bash).
# shellcheck source=SCRIPTDIR/lib/driver-verdict.sh
source "$SCRIPT_DIR/lib/driver-verdict.sh"

# Shared weighted risk scoring (M-14) -- same model + same config file as
# insights-rules/plugins/risk_scoring.py.
# shellcheck source=SCRIPTDIR/lib/risk-scoring.sh
source "$SCRIPT_DIR/lib/risk-scoring.sh"

# F-05: Thanos/Prometheus query helper for Gate 11's storage-latency verdict.
# shellcheck source=SCRIPTDIR/lib/prom-query.sh
source "$SCRIPT_DIR/lib/prom-query.sh"

# Storage-latency thresholds for Gate 11 (KCS-7132512), same source of truth as
# the Prometheus alerts and cnv-storage-latency-calibrate.sh. Seconds per I/O
# operation -- NOT the millisecond scale the Python analyzer's guest-side
# early-warning rule uses; the two are deliberately different (see
# shared/storage-latency-thresholds.json's _units).
_SLT="$SCRIPT_DIR/../shared/storage-latency-thresholds.json"
[ -f "$_SLT" ] || _SLT="/usr/share/bsod-detection/shared/storage-latency-thresholds.json"
if [ -f "$_SLT" ]; then
  LAT_WARN_SECONDS=$(jq -r '.sustained_warn_seconds // 0.5' "$_SLT" 2>/dev/null)
  LAT_CRIT_SECONDS=$(jq -r '.sustained_critical_seconds // 1.0' "$_SLT" 2>/dev/null)
else
  LAT_WARN_SECONDS="0.5"
  LAT_CRIT_SECONDS="1.0"
fi

# --- Stop-code filtering helpers ---
# Normalize comma-separated stop codes to an uppercase set for matching.
declare -A ACTIVE_STOP_CODES=()
if [ -n "$STOP_CODES" ]; then
  IFS=',' read -ra _sc_arr <<< "$STOP_CODES"
  for _sc in "${_sc_arr[@]}"; do
    _sc_upper=$(echo "$_sc" | tr '[:lower:]' '[:upper:]')
    # Normalize: ensure 0x prefix
    case "$_sc_upper" in
      0X*) ACTIVE_STOP_CODES["$_sc_upper"]=1 ;;
      *)   ACTIVE_STOP_CODES["0X$_sc_upper"]=1 ;;
    esac
  done
fi

# gate_enabled <gate_number>: returns 0 if the gate should run, 1 if skipped.
gate_enabled() {
  local gate="$1"
  if [ "${#ACTIVE_STOP_CODES[@]}" -eq 0 ]; then
    return 0
  fi
  local codes="${GATE_STOP_CODES[$gate]:-}"
  # N11: "*" is the always-on sentinel (currently only Gate 20) -- must be
  # checked BEFORE the empty-string-means-disabled branch below, or a gate
  # meant to be stop-code-agnostic is silently disabled by any --stop-code use.
  if [ "$codes" = "*" ]; then
    return 0
  fi
  if [ -z "$codes" ]; then
    return 1
  fi
  IFS=',' read -ra _gate_codes <<< "$codes"
  for _gc in "${_gate_codes[@]}"; do
    local _gc_upper
    _gc_upper=$(echo "$_gc" | tr '[:lower:]' '[:upper:]')
    if [ "${ACTIVE_STOP_CODES[$_gc_upper]:-}" = "1" ]; then
      return 0
    fi
  done
  return 1
}

# --- Output helpers ---
# JSON findings accumulator
declare -a JSON_FINDINGS_CLUSTER=()
declare -a JSON_FINDINGS_VMS=()
CURRENT_VM_NS=""
CURRENT_VM_NAME=""
CURRENT_VM_OS=""
declare -a CURRENT_VM_FINDINGS=()
# L-11: plain severity/message shadows of CURRENT_VM_FINDINGS. Text mode needs
# only these two fields (for the per-VM summary line), so it can skip building
# -- and later re-parsing with jq -- the full JSON record for every finding.
declare -a CURRENT_VM_SEV=()
declare -a CURRENT_VM_MSG=()

# True when some consumer will actually read the JSON finding records.
_json_needed() { [ -n "$JSON_MODE" ] || [ -n "$OUTPUT_DIR" ]; }

# Namespace-level counters for multi-namespace summary
declare -A NS_VM_COUNT=()
declare -A NS_FAIL_COUNT=()
declare -A NS_WARN_COUNT=()
declare -A NS_UNKNOWN_COUNT=()
declare -A NS_PASS_COUNT=()

_IN_VM_LOOP=0
_no_output() { [ "$JSON_MODE" != "" ] || [ "$SUMMARY_ONLY" -eq 1 ]; }
red()   { _no_output && return; if [ "$USE_COLOR" -eq 1 ]; then printf '\033[31m%s\033[0m\n' "$*"; else echo "$*"; fi; }
amber() { _no_output && return; if [ "$USE_COLOR" -eq 1 ]; then printf '\033[33m%s\033[0m\n' "$*"; else echo "$*"; fi; }
green() { _no_output && return; if [ "$USE_COLOR" -eq 1 ]; then printf '\033[32m%s\033[0m\n' "$*"; else echo "$*"; fi; }
info()  { _no_output && return; echo "$*"; }

# Risk tier via the SHARED weighted model (shared/risk-scoring.json), identical
# to insights-rules/plugins/risk_scoring.py. Cross-layer agreement is pinned by
# shared/risk-tier-test-vectors.json.
#
# The previous implementation counted FAILs/WARNs and only "approximated" the
# Python thresholds -- measured on identical finding sets the two disagreed on
# 3 of 4 representative cases, in both directions, while printing the same
# CRITICAL/HIGH/MEDIUM/LOW vocabulary to operators (M-14).
#
# Falls back to the old count-based heuristic ONLY if the shared library or
# jq is unavailable, and that fallback deliberately biases upward.
risk_tier() {
  local fails=$1 warns=$2
  if [ "${RS_CONFIG_LOADED:-0}" -eq 1 ]; then
    local total; total=$(rs_total)
    if [ "$fails" -eq 0 ] && [ "$warns" -eq 0 ] && [ "${total:-0}" -eq 0 ]; then
      echo "PASS"
    else
      rs_tier "$total"
    fi
    return
  fi
  # Degraded fallback: no shared config. Bias toward over-reporting.
  if [ "$fails" -ge 2 ]; then echo "CRITICAL"
  elif [ "$fails" -ge 1 ]; then echo "HIGH"
  elif [ "$warns" -ge 4 ]; then echo "MEDIUM"
  elif [ "$warns" -ge 1 ]; then echo "LOW"
  else echo "PASS"; fi
}

FINDINGS=0
WARNINGS=0
# Checks that could not be evaluated (missing/uninterpretable evidence).
# Tracked separately from WARNINGS so "we found a risk" and "we could not look"
# are never conflated in the summary or in downstream consumers.
UNKNOWNS=0
# R-21: count of [ OK ] verdicts, for the evidence-completeness denominator.
# FINDINGS/WARNINGS/UNKNOWNS were already tracked; passes were not, because
# nothing needed "how many checks actually reached a verdict" until evidence
# completeness became its own reported axis. Declared HERE, with its siblings,
# rather than beside TOTAL_PASS further down -- under `set -u` the cluster-scope
# gates call ok() long before that later block executes.
PASSES=0
# Issue K (v0.19.0 peer-review, gitlab-issue-drafts-open-after-remediation.md):
# fleet-wide running totals mirroring each VM's own _vm_assessed/_vm_total
# (see the per-VM evidence-completeness comment below), so a single fleet
# percentage can be reported alongside the existing per-VM ones without a
# second pass over the VM list. Weighted by checks-per-VM (not a simple
# average of per-VM percentages), so a VM with more reachable checks
# contributes proportionally more to the fleet figure -- consistent with the
# per-VM formula's own "of what we tried to assess" framing at fleet scale.
FLEET_ASSESSED_TOTAL=0
FLEET_CHECKS_TOTAL=0

# Per-VM verdict tracking for executive summary and cluster-wide pattern detection
declare -a EXEC_FAIL_VMS=()
declare -a EXEC_FAIL_DETAILS=()
declare -a EXEC_VM_NAMES=()
declare -a EXEC_VM_NS=()
declare -a EXEC_VM_FAILS=()
declare -a EXEC_VM_WARNS=()
declare -a EXEC_VM_UNKNOWNS=()
declare -a EXEC_VM_TOP_ISSUE=()
declare -a EXEC_VM_TIER=()
# Gate-level hit counters for cluster-wide pattern detection
declare -A GATE_WARN_COUNT=()
declare -A GATE_WARN_MSG=()
# Count per-gate deferrals for "VMI not running" collapse
declare -A GATE_DEFERRED_COUNT=()
EVIDENCE_GAP_COUNT=0

# emit_finding <severity> <gate> <message> [kcs] [stop_code] [confidence]
emit_finding() {
  local severity="$1" gate="$2" message="$3"
  local kcs="${4:-}" stop_code="${5:-}" confidence="${6:-}"

  if [ -z "$confidence" ]; then
    if [ -n "$kcs" ]; then
      confidence="KCS-VALIDATED"
    else
      confidence="GENERAL-KNOWLEDGE"
    fi
  fi
  if [ -z "$stop_code" ]; then
    stop_code="${GATE_STOP_CODES[$gate]:-}"
    # N11: "*" is gate_enabled()'s always-on sentinel (currently only Gate
    # 20), never a real stop code -- never let it leak into a finding's
    # stop_code field/JSON output.
    [ "$stop_code" = "*" ] && stop_code=""
  fi

  case "$severity" in
    FAIL)
      if ! _no_output; then
        if [ "$USE_COLOR" -eq 1 ]; then printf '\033[31m  [FAIL] %s\033[0m\n' "$message"
        else printf '  [FAIL] %s\n' "$message"; fi
      fi
      FINDINGS=$((FINDINGS+1))
      ;;
    WARN)
      if ! _no_output; then
        if [ "$USE_COLOR" -eq 1 ]; then printf '\033[33m  [WARN] %s\033[0m\n' "$message"
        else printf '  [WARN] %s\n' "$message"; fi
      fi
      WARNINGS=$((WARNINGS+1))
      ;;
    UNKNOWN)
      # Required evidence was missing or uninterpretable -- the gate could not
      # reach a verdict. Deliberately NOT counted as a WARN (it is not a risk
      # finding) and NOT as OK (it is not a pass). Does not affect the exit
      # code, but MUST be visible in the summary: exit 0 with UNKNOWNs present
      # does not mean migration-safe.
      if ! _no_output; then
        if [ "$USE_COLOR" -eq 1 ]; then printf '\033[36m  [UNKN] %s\033[0m\n' "$message"
        else printf '  [UNKN] %s\n' "$message"; fi
      fi
      UNKNOWNS=$((UNKNOWNS+1))
      ;;
    OK)
      if ! _no_output; then
        if [ "$USE_COLOR" -eq 1 ]; then printf '\033[32m  [ OK ] %s\033[0m\n' "$message"
        else printf '  [ OK ] %s\n' "$message"; fi
      fi
      ;;
    *)
      # M4: an unrecognized severity must FAIL LOUDLY, never vanish.
      #
      # This case statement previously had no default branch, so a typo'd
      # severity printed NOTHING while still reaching rs_add below -- inflating
      # the VM's risk tier with a finding invisible in the report and in every
      # counter. Mirrors the Python half, where RuleResult now coerces an
      # unrecognized severity to FAIL at construction rather than letting the
      # scoring and reporting layers disagree.
      if ! _no_output; then
        if [ "$USE_COLOR" -eq 1 ]; then printf '\033[31m  [FAIL] (unrecognized severity %s) %s\033[0m\n' "$severity" "$message"
        else printf '  [FAIL] (unrecognized severity %s) %s\n' "$severity" "$message"; fi
      fi
      severity="FAIL"
      FINDINGS=$((FINDINGS+1))
      ;;
  esac

  # L-11: the per-finding jq fork only happens when JSON is actually consumed.
  # emit_finding previously forked jq for EVERY finding unconditionally --
  # roughly 20 per VM, so a 27-VM namespace paid ~540 process spawns to build
  # records that a plain text run then threw away. The text-mode summary line
  # needs only severity+message, so those are kept in parallel plain arrays.
  CURRENT_VM_SEV+=("$severity")
  CURRENT_VM_MSG+=("$message")

  # NOTE: only the JSON construction below is skipped in text mode. Scoring
  # (rs_add), gate-WARN tracking and the counters further down must run on
  # EVERY invocation -- returning early here would silently disable risk tiers
  # and cluster-wide pattern detection for every non-JSON run.
  local finding_json=""
  if _json_needed; then
    finding_json=$(jq -n \
      --argjson gate "$gate" \
      --arg severity "$severity" \
      --arg stop_code "$stop_code" \
      --arg message "$message" \
      --arg kcs "$kcs" \
      --arg confidence "$confidence" \
      '{gate: $gate, severity: $severity, stop_code: $stop_code, message: $message, kcs: $kcs, confidence: $confidence}')
  fi

  if [ "$JSON_MODE" = "ndjson" ] && [ "$severity" != "OK" ]; then
    local ndjson_obj
    ndjson_obj=$(jq -c -n \
      --arg type "finding" \
      --arg namespace "$CURRENT_VM_NS" \
      --arg vm "$CURRENT_VM_NAME" \
      --argjson gate "$gate" \
      --arg severity "$severity" \
      --arg stop_code "$stop_code" \
      --arg message "$message" \
      --arg kcs "$kcs" \
      --arg confidence "$confidence" \
      '{type: $type, namespace: $namespace, vm: $vm, gate: $gate, severity: $severity, stop_code: $stop_code, message: $message, kcs: $kcs, confidence: $confidence}')
    echo "$ndjson_obj"
  fi

  if [ "$severity" != "OK" ] && [ -n "$finding_json" ]; then
    CURRENT_VM_FINDINGS+=("$finding_json")
  fi

  # Feed the shared weighted scorer (per-VM only). Cluster-scope findings are
  # summarised separately and must not inflate an individual VM's tier.
  if [ "$severity" != "OK" ] && [ "$_IN_VM_LOOP" -eq 1 ] \
     && [ "${RS_CONFIG_LOADED:-0}" -eq 1 ]; then
    rs_add "$severity" "$gate" "$kcs"
  fi

  # Track per-gate WARN counts for cluster-wide pattern detection (per-VM only)
  if [ "$severity" = "WARN" ] && [ "$gate" -gt 0 ] 2>/dev/null && [ "$_IN_VM_LOOP" -eq 1 ]; then
    GATE_WARN_COUNT[$gate]=$(( ${GATE_WARN_COUNT[$gate]:-0} + 1 ))
    if [ -z "${GATE_WARN_MSG[$gate]:-}" ]; then
      # Strip VM-specific name to make the message generic for cluster-wide display
      local _generic_msg="$message"
      if [ -n "$CURRENT_VM_NAME" ]; then
        _generic_msg="${_generic_msg//"$CURRENT_VM_NAME"/...}"
        _generic_msg="${_generic_msg// for .../}"
      fi
      GATE_WARN_MSG[$gate]="$_generic_msg"
    fi
  fi
}

flag() {
  local gate="${CURRENT_GATE:-0}" kcs="${CURRENT_KCS:-}" stop="${CURRENT_STOP_CODE:-}"
  emit_finding "FAIL" "$gate" "$*" "$kcs" "$stop"
}
warn() {
  local gate="${CURRENT_GATE:-0}" kcs="${CURRENT_KCS:-}" stop="${CURRENT_STOP_CODE:-}"
  emit_finding "WARN" "$gate" "$*" "$kcs" "$stop"
}
# _gate6_livemigrate_verdict <source-description>
# R-03 (v0.19.0 unified review U-02): grade an EFFECTIVE evictionStrategy of
# LiveMigrate against the VMI's LiveMigratable status condition.
#
# Shared by both paths that can produce that effective value -- an explicit
# spec.template.spec.evictionStrategy, and an unset field inheriting the
# HyperConverged/KubeVirt cluster default. KubeVirt resolves the default onto
# the VMI either way, so both carry the identical force-delete hazard. The
# first cut of this fix wired the condition into the explicit branch only, and
# a live run immediately exposed the gap: win11-oversocket (evictionStrategy
# unset, inheriting LiveMigrate, LiveMigratable=False) was still reported OK
# while BSODRisk_EvictionBlocked fired on it.
#
# Reads: _vmi_present, _lm_status, _lm_reason, v (VM name) from the caller's
# per-VM scope.
_gate6_livemigrate_verdict() {
  local _src="${1:-explicit}" _lm_msg
  if [ "${_vmi_present:-0}" != "1" ]; then
    # Stopped VM: DEFER the migratability sub-check rather than emit UNKNOWN.
    # A stopped VM has no pod to evict, so the hazard this gate detects (PDB
    # blocks eviction -> force-delete -> dirty shutdown) is inapplicable at
    # assessment time, not merely unmeasured. Gates 11 and 13 already use this
    # idiom for the same reason, and deferrals are surfaced in the "DEFERRED
    # CHECKS (VM not running -- start VMs and rerun)" summary section -- visible
    # without inflating the UNASSESSED count that --fail-on-unknown blocks on.
    #
    # (Emitting UNKNOWN here would also make a clean audit harder to reach.
    # Until v0.28.0 Gate 11 emitted UNKNOWN unconditionally for running VMs, so
    # a fully clean audit was impossible by construction; F-05 gave Gate 11 a
    # real verdict, but the argument for deferring here stands on its own --
    # "not running" is a known state, not missing evidence.)
    #
    # The spec field itself IS checkable while stopped and is still graded --
    # evictionStrategy=None remains a FAIL for a stopped VM.
    ok "evictionStrategy=LiveMigrate ($_src; spec correct, live-migratability deferred -- $v is not running)"
    GATE_DEFERRED_COUNT[6]=$(( ${GATE_DEFERRED_COUNT[6]:-0} + 1 ))
    return
  fi
  if [ "${_lm_status:-}" = "False" ]; then
    _lm_msg="evictionStrategy=LiveMigrate ($_src) but the VMI reports LiveMigratable=False"
    [ -n "${_lm_reason:-}" ] && _lm_msg="$_lm_msg (reason: $_lm_reason)"
    _lm_msg="$_lm_msg -- on node drain the PodDisruptionBudget will block eviction and the pod will be force-deleted after the drain timeout, causing a dirty shutdown that can trigger or masquerade as a BSOD. Fix the migration blocker, or set evictionStrategy=LiveMigrateIfPossible so the VM is stopped gracefully instead"
    if [ "${_lm_reason:-}" = "NoTSCFrequencyNotLiveMigratable" ]; then
      _lm_msg="$_lm_msg. See Gate 12: this cluster has no tsc-frequency scheduling labels, which is the root cause for HyperV-reenlightenment Windows VMs"
    fi
    warn_strict "$_lm_msg"
  elif [ "${_lm_status:-}" = "True" ]; then
    ok "LiveMigrate ($_src) and VMI reports LiveMigratable=True (node drain will live-migrate, not hard-reset)"
  else
    unknown "evictionStrategy=LiveMigrate ($_src), but the VMI exposes no LiveMigratable condition for $v -- cannot confirm the VM will actually migrate on drain"
  fi
}

warn_strict() {
  if [ "$STRICT" -eq 1 ]; then
    flag "$*"
  else
    warn "$*"
  fi
}
# unknown(): the gate could not reach a verdict because required evidence was
# absent. Never use ok() for this -- reporting a pass on evidence that was never
# collected is the single most damaging failure mode this framework has.
unknown() {
  local gate="${CURRENT_GATE:-0}" kcs="${CURRENT_KCS:-}" stop="${CURRENT_STOP_CODE:-}"
  emit_finding "UNKNOWN" "$gate" "$*" "$kcs" "$stop"
}
ok() {
  local gate="${CURRENT_GATE:-0}" kcs="${CURRENT_KCS:-}" stop="${CURRENT_STOP_CODE:-}"
  PASSES=$((PASSES+1))
  emit_finding "OK" "$gate" "$*" "$kcs" "$stop"
}

# Helper for setting gate context before each gate block
set_gate() {
  CURRENT_GATE="$1"
  CURRENT_KCS="${2:-}"
  # N11: use argument COUNT, not bash's ${3:-default} (which cannot
  # distinguish "arg 3 omitted" from "arg 3 explicitly passed as ''"). Gate
  # 20 deliberately calls `set_gate 20 "" ""` to override the map lookup with
  # an explicit "no stop code" -- with ${3:-...}, that empty string is
  # indistinguishable from "not passed" and falls through to
  # GATE_STOP_CODES[20], which is now the "*" always-on sentinel. Every Gate
  # 20 finding would otherwise get a literal stop_code of "*".
  if [ "$#" -ge 3 ]; then
    CURRENT_STOP_CODE="$3"
  else
    CURRENT_STOP_CODE="${GATE_STOP_CODES[$1]:-}"
  fi
}

# _gate20_suggest_cmd <ns> <name> <os_label> <template_prefix>
# Issue I: factored out of Gate 20's cluster-scope --suggest-annotate loop so
# the SAME suggestion logic (and the exact same N24 oc-patch-not-oc-annotate
# fix it carries) is reachable from both the cluster-scope aggregate list AND
# the new per-VM finding below -- a suggestion an operator can act on directly
# from the VM's own output, not only by cross-referencing a separate
# cluster-scope list.
_gate20_suggest_cmd() {
  local _sa_ns="$1" _sa_name="$2" _sa_os_label="$3" _sa_tmpl_prefix="$4"
  local _sa_value="" _sa_source=""
  if echo "$_sa_os_label" | grep -qiE '^(windows|win.*)$'; then
    _sa_value="$_sa_os_label"; _sa_source="from existing vm.kubevirt.io/os label"
  elif echo "$_sa_tmpl_prefix" | grep -qiE '^(windows|win.*)$'; then
    _sa_value="$_sa_tmpl_prefix"; _sa_source="from vm.kubevirt.io/template label prefix"
  else
    _sa_value="windows"; _sa_source="GENERIC FALLBACK -- VERIFY the exact edition/version against the guest before applying"
  fi
  info "    oc patch vm $_sa_name -n $_sa_ns --type=merge -p '{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"vm.kubevirt.io/os\":\"$_sa_value\"}}}}}'   # $_sa_source"
}

if ! command -v jq >/dev/null 2>&1; then red "jq is required"; exit 2; fi
if ! command -v oc >/dev/null 2>&1; then red "oc is required"; exit 2; fi

# Resolve --all-namespaces after confirming oc is available
if [ "$ALL_NAMESPACES" -eq 1 ]; then
  if ! _all_ns_json=$(timeout 120 oc get vm -A -o json 2>/dev/null) || [ -z "$_all_ns_json" ]; then
    red "Failed to list VMs across all namespaces (check RBAC: needs cluster-wide list on virtualmachines.kubevirt.io)"
    exit 2
  fi
  mapfile -t NAMESPACES < <(echo "$_all_ns_json" | jq -r '[.items[].metadata.namespace] | unique | .[]')
  if [ "${#NAMESPACES[@]}" -eq 0 ]; then
    red "No VMs found in any namespace"; exit 1
  fi
fi

# Create output directory if requested
if [ -n "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR" 2>/dev/null || { red "Cannot create output directory: $OUTPUT_DIR"; exit 2; }
fi

# --- Pre-compute cluster-scoped data (gates 8, 9, 12) once ---
# Avoids O(VMs x nodes) API amplification per M-1.
AMD_MICROCODE_FIX="0xb002151"
AMD_MICROCODE_FIX_DEC=$((0xb002151))
CACHED_NODES_JSON=""
CACHED_AMD_RISK=0
CACHED_CPU_VENDOR_AMD=0
CACHED_AMD_FAMILY1A_NODES=""
CACHED_AMD_INFO=""
# Count of AMD nodes whose cpu-family label is missing. Gate 8 cannot assess
# the KCS-7132511 (0x4E) Family 1Ah risk for these -- it must NOT report [ OK ].
CACHED_AMD_UNKNOWN_FAMILY=0
CACHED_CLUSTER_EVICTION=""
CACHED_CLUSTER_EVICTION_SOURCE=""
# Probe microcode via oc debug (opt-out with BSOD_SKIP_MICROCODE_PROBE=1 for air-gapped/CI)
SKIP_MICROCODE_PROBE="${BSOD_SKIP_MICROCODE_PROBE:-0}"

probe_node_microcode() {
  local node="$1"
  local raw=""
  # shellcheck disable=SC2016
  raw=$(timeout 45 oc debug "node/${node}" --quiet -- \
    bash -c \
    'cat /host/sys/devices/system/cpu/cpu0/microcode/version 2>/dev/null || grep -m1 -i microcode /host/proc/cpuinfo 2>/dev/null | awk "{print \$NF}" || true' \
    2>/dev/null | tr -d '\r' | tail -n1 | tr -d '[:space:]')
  echo "$raw"
}

# H3 (v0.16.0): distinguish "the API returned nothing" from "the API call
# failed". Every cluster fetch used to be
#     $(oc get ... 2>/dev/null || echo '{"items":[]}')
# which discards the error text AND substitutes a well-formed empty result. A
# gate reading that empty result cannot tell a healthy cluster with no AMD
# nodes from a cluster it was never allowed to read -- so an expired token or a
# missing ClusterRoleBinding produced `[ OK ]` verdicts and exit 0. Confirmed:
# `--cluster-scope-only` against a dead API server returned exit 0 with SIX
# `[ OK ]` lines, and an RBAC-restricted run reported
# `[ OK ] arch-capabilities check passed (... amd_nodes=0)` -- a KCS-7125237
# (0x5D) check passing *because* it could not read the nodes.
#
# This is the same false-PASS class the UNKNOWN severity contract exists to
# eliminate, one layer below the rules: the contract was enforced meticulously
# above the data layer and not at all within it.
#
# _oc_fetch sets <var> to the JSON on success, or to '{"items":[]}' plus a
# companion <var>_ERR=1 on failure. Gates MUST consult the _ERR flag before
# concluding anything from an empty result -- see _require_evidence below.
# R-23 (v0.19.0 unified review U-21): cluster-scope fetches that a fleet caller
# may inject from a warm cache instead of re-fetching per VM.
#
# cnv-mtv-plan-gate.sh spawns a FRESH audit process per VM, and every one of
# them re-fetched the worker node list, the Windows templates, the cluster
# instancetypes and the cluster preferences -- data that is identical for every
# VM in the wave. At 500-1000 VM wave scale that is thousands of redundant
# apiserver calls and minutes of wall-clock on the migration-blocking path.
#
# ALLOWLIST, not a blanket cache. Namespace-scoped and status-bearing fetches
# (CACHED_VM_LIST_JSON, CACHED_VMI_LIST_JSON) are deliberately excluded: VMI
# status carries LiveMigratable and phase, which Gate 6 and Gate 13 read and
# which genuinely change between VMs in a wave. Serving those from a stale
# snapshot would reintroduce a verdict drawn from evidence that no longer holds.
_OC_CACHEABLE=" CACHED_NODES_JSON CACHED_TEMPLATES_JSON CACHED_CLUSTER_INSTANCETYPES_JSON CACHED_CLUSTER_PREFERENCES_JSON CACHED_SCOPE_VM_JSON "

_oc_cache_path() {  # _oc_cache_path <var-name> -> path, or empty if not cacheable
  local __v="$1"
  [ -n "${BSOD_CLUSTER_CACHE_DIR:-}" ] || return 0
  case "$_OC_CACHEABLE" in *" $__v "*) printf '%s/%s.json' "$BSOD_CLUSTER_CACHE_DIR" "$__v" ;; esac
}

_oc_fetch() {   # _oc_fetch <var-name> <what> -- <oc args...>
  local __var="$1" __what="$2"; shift 3
  local __out __rc __attempt=0 __cache

  # Warm-cache hit: skip the API entirely.
  __cache=$(_oc_cache_path "$__var")
  if [ -n "$__cache" ] && [ -s "$__cache" ]; then
    printf -v "$__var" '%s' "$(cat "$__cache")"
    printf -v "${__var}_ERR" '%s' '0'
    return 0
  fi

  # R-24 (v0.19.0 unified review U-22): retry TRANSIENT failures.
  #
  # There was no retry anywhere, so a single 429 or 5xx during a fleet audit
  # turned that fetch into a permanent UNKNOWN for the whole run -- and under
  # --fail-on-unknown (the PreHook default) that BLOCKS a migration wave on a
  # blip. Retrying is the correct response to a rate-limit or an apiserver
  # rolling restart; it is emphatically NOT the correct response to an RBAC
  # denial or a bad request, which will fail identically every time and whose
  # UNKNOWN is a true finding the operator needs to see immediately.
  #
  # BSOD_OC_RETRIES=0 disables retry entirely (offline fixture harnesses set
  # this so mock-oc failure scenarios stay instantaneous and deterministic).
  local __max="${BSOD_OC_RETRIES:-2}"
  while :; do
    __out=$(timeout 120 oc "$@" -o json 2>&1); __rc=$?
    [ "$__rc" -eq 0 ] && [ -n "$__out" ] && break
    [ "$__attempt" -ge "$__max" ] && break
    # Retry only what a retry can plausibly fix. Anything matching a permanent
    # authz/validation error is returned immediately.
    if printf '%s' "$__out" | grep -qiE 'forbidden|unauthorized|cannot list|not found|no matches for kind|invalid|bad request'; then
      break
    fi
    __attempt=$((__attempt + 1))
    sleep $((__attempt * 2))   # 2s, 4s
  done
  if [ "$__attempt" -gt 0 ] && [ "$__rc" -eq 0 ]; then
    info "  (recovered $__what after $__attempt retry attempt(s))"
  fi

  if [ "$__rc" -ne 0 ] || [ -z "$__out" ]; then
    printf -v "$__var" '%s' '{"items":[]}'
    printf -v "${__var}_ERR" '%s' '1'
    # First line only: oc errors can be multi-line, and the gate output is
    # meant to stay scannable.
    ACQUISITION_ERRORS="${ACQUISITION_ERRORS}${__what}: ${__out%%$'\n'*}"$'\n'
    return 1
  fi
  printf -v "$__var" '%s' "$__out"
  printf -v "${__var}_ERR" '%s' '0'
  # R-23: warm the cache for subsequent per-VM invocations. Only successful
  # fetches are written -- caching a failure would turn one transient outage
  # into a whole wave's worth of UNKNOWNs, the opposite of R-24's intent.
  if [ -n "$__cache" ]; then
    mkdir -p "$BSOD_CLUSTER_CACHE_DIR" 2>/dev/null && \
      printf '%s' "$__out" > "$__cache" 2>/dev/null || true
  fi
  return 0
}

# _require_evidence <err-flag> <what> -- emit [UNKN] and return 1 when the
# evidence behind a check was never readable. Callers use it as:
#   if _require_evidence "$CACHED_NODES_JSON_ERR" "worker nodes"; then ok "..."; fi
_require_evidence() {
  local __err="${1:-0}" __what="$2"
  if [ "$__err" = "1" ]; then
    unknown "$__what could not be read from the cluster -- this check could not be evaluated (see ACQUISITION ERRORS above). Absence of evidence is not evidence of absence."
    return 1
  fi
  return 0
}

ACQUISITION_ERRORS=""
# R-13: records which nodes had their AMD family inferred from host-model-cpu
# rather than an explicit cpu-family label, so the Gate 8 output can say so.
CACHED_AMD_FAMILY_SOURCE=""

if command -v oc >/dev/null 2>&1; then
  _oc_fetch CACHED_NODES_JSON "worker nodes" -- get nodes -l node-role.kubernetes.io/worker
  CACHED_SCHEDULABLE_NODES=$(echo "$CACHED_NODES_JSON" | jq -r '.items[].metadata.name')
  for node in $CACHED_SCHEDULABLE_NODES; do
    node_json=$(echo "$CACHED_NODES_JSON" | jq --arg n "$node" '.items[] | select(.metadata.name == $n)')
    is_amd=$(echo "$node_json" | jq -r '
      [.metadata.labels | to_entries[]
       | select(.key | test("cpu-vendor.*AMD"; "i"))] | length')
    if [ "${is_amd:-0}" -gt 0 ]; then
      CACHED_CPU_VENDOR_AMD=1
      # R-13 (v0.19.0 unified review U-06): derive the AMD family from a label
      # KubeVirt ACTUALLY EMITS.
      #
      # This read only `cpu-family.*node.kubevirt.io`, which KubeVirt has never
      # emitted -- a full label census on CNV 4.18.8 and 4.21.13 returned
      # cpu-feature, cpu-model, cpu-model-migration, cpu-vendor, host-model-cpu,
      # host-model-required-features, hyperv and machine-type, and nothing
      # containing "family". CACHED_AMD_RISK could therefore never be set, which
      # made the ENTIRE Gate 8 microcode block -- including the already-written,
      # already-opt-out-guarded `probe_node_microcode()` oc-debug probe -- dead
      # code on every stock cluster. Gate 8 emitted [UNKN] on 100% of AMD nodes.
      #
      # Three of the six v0.19.0 reviews recommended ADDING a microcode probe;
      # one (Gemini-3.1-Pro) correctly pointed out it already existed. The real
      # defect was never the probe -- it was the gate in front of it.
      #
      # host-model-cpu.node.kubevirt.io/<model> IS emitted (observed:
      # EPYC-Milan, EPYC-Rome) and is sufficient to RULE OUT Family 1Ah, which
      # is the common case. Zen mapping: Rome=17h, Milan/Genoa=19h, Turin=1Ah.
      # KCS-7132511 concerns "AMD Family 1Ah Models 00h-0Fh" (verified against
      # the source PDF), so only Turin-class parts are exposed.
      #
      # FAIL-SAFE: an UNRECOGNISED model must stay "unknown" (-> [UNKN]), never
      # be cleared. A future EPYC codename is exactly the case that must not be
      # silently passed.
      cpu_family=$(echo "$node_json" | jq -r '
        [.metadata.labels | to_entries[]
         | select(.key | test("cpu-family.*node.kubevirt.io"))]
        | .[0].key // "" | if . == "" then "unknown" else (split("/")[1] // "unknown") end')
      if [ "$cpu_family" = "unknown" ]; then
        host_model=$(echo "$node_json" | jq -r '
          [.metadata.labels | to_entries[]
           | select(.key | test("host-model-cpu.node.kubevirt.io"))]
          | .[0].key // "" | if . == "" then "" else (split("/")[1] // "") end')
        case "$(printf '%s' "$host_model" | tr '[:upper:]' '[:lower:]')" in
          *turin*)                 cpu_family="26" ;;   # Zen 5, Family 1Ah -- the KCS-7132511 family
          *rome*|*naples*)         cpu_family="23" ;;   # Zen 2 / Zen 1, Family 17h
          *milan*|*genoa*|*bergamo*|*siena*) cpu_family="25" ;;  # Zen 3 / Zen 4, Family 19h
          *)                       : ;;                 # unrecognised -> stays "unknown"
        esac
        [ "$cpu_family" != "unknown" ] && \
          CACHED_AMD_FAMILY_SOURCE="${CACHED_AMD_FAMILY_SOURCE}${node}=host-model-cpu/${host_model}"$'\n'
      fi
      if [ "$cpu_family" = "26" ] || [ "$cpu_family" = "0x1a" ]; then
        CACHED_AMD_RISK=1
        CACHED_AMD_FAMILY1A_NODES="${CACHED_AMD_FAMILY1A_NODES}${node}"$'\n'
      elif [ "$cpu_family" = "unknown" ]; then
        CACHED_AMD_UNKNOWN_FAMILY=$((CACHED_AMD_UNKNOWN_FAMILY+1))
        CACHED_AMD_INFO="${CACHED_AMD_INFO}node $node: AMD node without cpu-family label -- cannot assess 0x4E risk; label node or verify microcode manually\n"
      fi
    fi
  done

  # TSC frequency labels (gate 12). KubeVirt never emits a bare
  # "scheduling.node.kubevirt.io/tsc-frequency" key -- confirmed live
  # 2026-08-13, the frequency is always in the KEY suffix (presence-style,
  # same convention as cpu-vendor.node.kubevirt.io/AMD=true), so a lookup for
  # that exact key can never match a real cluster and always fell through to
  # "no TSC frequency labels found", masking a genuine live mismatch. Prefer
  # cpu-timer.node.kubevirt.io/tsc-frequency (one per node, value IS the
  # frequency, unambiguous); fall back to the scheduling label only when a
  # node carries exactly one distinct suffix (more than one means this node
  # is schedulable against multiple TSC buckets via tsc-scalable=true, and we
  # cannot tell which one is its own).
  CACHED_TSC_LABELS=$(echo "$CACHED_NODES_JSON" | jq -r '
    .items[] | . as $n |
    ($n.metadata.labels["cpu-timer.node.kubevirt.io/tsc-frequency"] // "") as $direct |
    ([$n.metadata.labels | keys[] | select(startswith("scheduling.node.kubevirt.io/tsc-frequency-")) | ltrimstr("scheduling.node.kubevirt.io/tsc-frequency-")] | unique) as $sched |
    (if $direct != "" then $direct elif ($sched | length) == 1 then $sched[0] else "" end) as $val |
    ($n.metadata.name + "=" + $val)' 2>/dev/null | grep -v '=$')

  # Pre-cache cluster-default eviction strategy (used by Gate 6 per-VM)
  CACHED_CLUSTER_EVICTION=$(oc get hyperconverged kubevirt-hyperconverged -n openshift-cnv \
    -o jsonpath='{.spec.virtualization.evictionStrategy}' 2>/dev/null)
  if [ -n "$CACHED_CLUSTER_EVICTION" ]; then
    CACHED_CLUSTER_EVICTION_SOURCE="hco-v1"
  fi
  if [ -z "$CACHED_CLUSTER_EVICTION" ]; then
    CACHED_CLUSTER_EVICTION=$(oc get hyperconverged kubevirt-hyperconverged -n openshift-cnv \
      -o jsonpath='{.spec.evictionStrategy}' 2>/dev/null)
    [ -n "$CACHED_CLUSTER_EVICTION" ] && CACHED_CLUSTER_EVICTION_SOURCE="hco-v1beta1"
  fi
  if [ -z "$CACHED_CLUSTER_EVICTION" ]; then
    CACHED_CLUSTER_EVICTION=$(oc get kubevirt -n openshift-cnv \
      -o jsonpath='{.items[0].spec.configuration.evictionStrategy}' 2>/dev/null)
    # shellcheck disable=SC2034 # reserved for JSON output / diagnostic context
    [ -n "$CACHED_CLUSTER_EVICTION" ] && CACHED_CLUSTER_EVICTION_SOURCE="kubevirt"
  fi

  # Pre-cache templates, instancetypes, preferences (Gates 17-19)
  CACHED_TEMPLATES_JSON=""
  CACHED_CLUSTER_INSTANCETYPES_JSON=""
  CACHED_CLUSTER_PREFERENCES_JSON=""

  # Determine instancetype API availability from thresholds
  INSTANCETYPE_GA="false"
  SPEC_EXPANSION="true"
  if [ -n "$THRESHOLDS_JSON" ] && [ -n "$STREAM" ]; then
    INSTANCETYPE_GA=$(echo "$THRESHOLDS_JSON" | jq -r \
      --arg stream "$STREAM" \
      'if .streams[$stream].instancetype_ga == true then "true" else "false" end')
    SPEC_EXPANSION=$(echo "$THRESHOLDS_JSON" | jq -r \
      --arg stream "$STREAM" \
      'if .streams[$stream].spec_expansion == false then "false" else "true" end')
  elif [ -n "$THRESHOLDS_JSON" ]; then
    # No stream detected but thresholds available; assume GA for OCP 4.14+
    INSTANCETYPE_GA="true"
    SPEC_EXPANSION="true"
  fi

  if gate_enabled 17; then
    _oc_fetch CACHED_TEMPLATES_JSON "Windows templates (openshift ns)" -- \
      get template -n openshift -l "template.kubevirt.io/type"
  fi

  if [ "$INSTANCETYPE_GA" = "true" ]; then
    # N13: fetched unconditionally, NOT under `gate_enabled 18`, for the same
    # reason cluster preferences (below) are unconditional: Gate 18 audits
    # instancetypes as objects, but the per-VM loop also uses this index to
    # resolve a stopped VM's effective domain (OCP 4.19+ sparse specs). Tying
    # the fetch to Gate 18 meant any --stop-code filter excluding
    # 0x20001/0x7B/0x5D silently disabled per-VM instancetype resolution as a
    # side effect, so the same VM audited with and without a stop-code filter
    # could yield different verdicts for reasons unrelated to that filter.
    _oc_fetch CACHED_CLUSTER_INSTANCETYPES_JSON "cluster instancetypes" -- \
      get virtualmachineclusterinstancetype
    CACHED_CLUSTER_INSTANCETYPES_INDEX=$(echo "$CACHED_CLUSTER_INSTANCETYPES_JSON" | jq '[.items[] | {key: .metadata.name, value: .}] | from_entries' 2>/dev/null || echo '{}')
    # Cluster preferences are fetched unconditionally, NOT under `gate_enabled
    # 19`. Gate 19 audits preferences as objects, but the per-VM loop also uses
    # this index to resolve a stopped VM's effective domain (OCP 4.19+ sparse
    # specs). Tying the fetch to Gate 19 meant any --stop-code filter excluding
    # 0x20001/0x7B/0x5D silently disabled per-VM resolution as a side effect,
    # so the same VM audited with and without a stop-code filter could yield
    # different verdicts for reasons unrelated to that filter.
    _oc_fetch CACHED_CLUSTER_PREFERENCES_JSON "cluster preferences" -- \
      get virtualmachineclusterpreference
    CACHED_CLUSTER_PREFERENCES_INDEX=$(echo "$CACHED_CLUSTER_PREFERENCES_JSON" | jq '[.items[] | {key: .metadata.name, value: .}] | from_entries' 2>/dev/null || echo '{}')
  fi
fi

# --- Header ---
if [ "$JSON_MODE" = "" ]; then
  echo "=============================================================="
  if [ "$ALL_NAMESPACES" -eq 1 ]; then
    echo " CNV Windows BSOD risk audit  --  all namespaces (${#NAMESPACES[@]} found)"
  elif [ "${#NAMESPACES[@]}" -gt 1 ]; then
    echo " CNV Windows BSOD risk audit  --  ${#NAMESPACES[@]} namespaces"
  else
    echo " CNV Windows BSOD risk audit  --  namespace: ${NAMESPACES[0]:-}"
  fi
  echo " Driver remediation baseline: virtio-win >= $DRIVER_BASELINE"
  if [ -n "$STREAM" ]; then
    echo " OCP version: ${OCP_VER} | RHEL stream: ${STREAM}"
    [ -n "$STREAM_NOTE" ] && echo " Stream note: $STREAM_NOTE"
    [ -n "$STREAM_FAIL" ] && echo " Stream FAIL threshold: < $STREAM_FAIL"
    [ -n "$STREAM_WARN" ] && echo " Stream WARN threshold: < $STREAM_WARN"
    [ -n "$STREAM_MAX" ] && echo " Stream ceiling (max available): $STREAM_MAX"
  fi
  if [ -n "$STOP_CODES" ]; then
    echo " Stop-code filter: $STOP_CODES"
  fi
  echo "=============================================================="
fi

# --- Cluster-scope report (gates 8, 9 cluster-level, 12) ---
# Suppressed when --per-vm-only is set (plan gate prints these once separately).
if [ "$PER_VM_ONLY" -eq 0 ]; then
  CURRENT_VM_NS="__cluster__"
  CURRENT_VM_NAME=""

  info ""
  info "============ CLUSTER-SCOPE CHECKS ============"

  # --- Shared in-scope VM list (R-14) ---------------------------------------
  # Fetched ONCE for every cluster-scope gate that needs the VM population.
  # Gate 20 previously fetched this itself, after Gate 12 had already run --
  # so Gate 12 had no way to ask "does any in-scope Windows VM use HyperV
  # Reenlightenment?" and had to emit its TSC finding unscored.
  #
  # Also retires the /tmp/.bsod_ac_$$ predictable temp file (CWE-377/59, the
  # only non-mktemp temp path in the gate scripts): the per-namespace results
  # are accumulated in a shell variable instead of a world-writable file whose
  # name is derived from the PID.
  #
  # H3 contract preserved: a namespace whose `oc get vm` FAILED must stay
  # distinguishable from one that genuinely has no VMs -- `jq -s` over an empty
  # stream yields a well-formed {"items":[]}, which previously let an unreadable
  # cluster report "no Windows VMs in scope".
  CACHED_SCOPE_VM_JSON=""
  CACHED_SCOPE_VM_JSON_ERR=0
  if [ "$ALL_NAMESPACES" -eq 1 ]; then
    CACHED_SCOPE_VM_JSON=$(timeout 120 oc get vm -A -o json 2>/dev/null) || CACHED_SCOPE_VM_JSON_ERR=1
  else
    _scope_vm_docs=""
    for _scope_ns in "${NAMESPACES[@]}"; do
      _scope_doc=$(timeout 120 oc get vm -n "$_scope_ns" -o json 2>/dev/null) || CACHED_SCOPE_VM_JSON_ERR=1
      [ -n "$_scope_doc" ] && _scope_vm_docs="${_scope_vm_docs}${_scope_doc}"$'\n'
    done
    CACHED_SCOPE_VM_JSON=$(printf '%s' "$_scope_vm_docs" | jq -s '{items: ([.[].items] | add // [])}' 2>/dev/null)
  fi
  [ -z "$CACHED_SCOPE_VM_JSON" ] && CACHED_SCOPE_VM_JSON_ERR=1

  # H3: show WHY checks below could not be evaluated. Without this the operator
  # sees a wall of [UNKN] with no cause; the underlying `oc` error text was
  # previously discarded by `2>/dev/null` and never surfaced anywhere.
  if [ -n "$ACQUISITION_ERRORS" ]; then
    info ""
    info "  !! ACQUISITION ERRORS -- the cluster API could not be read:"
    while IFS= read -r _ae; do
      [ -n "$_ae" ] && info "     $_ae"
    done <<< "$ACQUISITION_ERRORS"
    # Deliberately avoids printing a literal "[ OK ]" here -- the string is
    # what tooling and the api-unavailable regression fixture grep for.
    info "     Checks depending on this data are reported as UNKNOWN, never as passing."
    info "     Common causes: expired token, missing ClusterRoleBinding (see tekton/rbac.yaml),"
    info "     or a namespaced ServiceAccount running a cluster-scoped audit."
    info ""
  fi

  if gate_enabled 8; then
    set_gate 8 "7132511" "0x4E"
    info "-- Gate 8: AMD microcode version (0x4E PFN_LIST_CORRUPT risk) --"
    if [ "$CACHED_AMD_RISK" -eq 1 ]; then
      while IFS= read -r amd_node; do
        [ -z "$amd_node" ] && continue
        if [ "$SKIP_MICROCODE_PROBE" = "1" ]; then
          warn "node $amd_node: AMD Family 1Ah -- microcode probe skipped (BSOD_SKIP_MICROCODE_PROBE=1); verify >= $AMD_MICROCODE_FIX manually (KCS-7132511)"
          continue
        fi
        mc_raw=$(probe_node_microcode "$amd_node")
        if [ -z "$mc_raw" ] || echo "$mc_raw" | grep -qiE 'UNAVAILABLE|error|denied|forbidden'; then
          warn "node $amd_node: AMD Family 1Ah -- could not read microcode via oc debug; verify >= $AMD_MICROCODE_FIX manually (KCS-7132511)"
          continue
        fi
        mc_norm="${mc_raw#0[xX]}"
        if ! printf '%d' "0x${mc_norm}" >/dev/null 2>&1; then
          warn "node $amd_node: AMD Family 1Ah -- unparseable microcode '$mc_raw'; verify >= $AMD_MICROCODE_FIX manually"
          continue
        fi
        mc_dec=$(printf '%d' "0x${mc_norm}")
        if [ "$mc_dec" -lt "$AMD_MICROCODE_FIX_DEC" ]; then
          flag "node $amd_node: AMD microcode 0x${mc_norm} < $AMD_MICROCODE_FIX -- PFN_LIST_CORRUPT (0x4E) risk (KCS-7132511)"
        else
          ok "node $amd_node: AMD microcode 0x${mc_norm} >= $AMD_MICROCODE_FIX"
        fi
      done < <(printf '%s' "$CACHED_AMD_FAMILY1A_NODES")
    elif [ "${CACHED_AMD_UNKNOWN_FAMILY:-0}" -gt 0 ]; then
      # Do NOT report [ OK ] here. AMD nodes are present but their cpu-family
      # label is missing, so Family 1Ah cannot be ruled in or out -- an
      # unlabelled Family 1Ah node would otherwise pass this gate silently.
      # Absence of the label is not absence of the 0x4E risk (KCS-7132511).
      unknown "${CACHED_AMD_UNKNOWN_FAMILY} AMD node(s) present but cpu-family label missing -- cannot determine Family 1Ah / 0x4E exposure. Verify microcode >= $AMD_MICROCODE_FIX manually, or label the node(s) (KCS-7132511)"
    else
      if _require_evidence "${CACHED_NODES_JSON_ERR:-0}" "worker node list"; then
        if [ -n "$CACHED_AMD_FAMILY_SOURCE" ]; then
          ok "no AMD Family 1Ah nodes detected -- family inferred from host-model-cpu label(s): $(printf '%s' "$CACHED_AMD_FAMILY_SOURCE" | tr '\n' ' ' | sed 's/ $//'). KCS-7132511 (0x4E) applies only to Family 1Ah (EPYC Turin)"
        else
          ok "no AMD Family 1Ah nodes detected (or no worker nodes schedulable)"
        fi
      fi
    fi
    if [ -n "$CACHED_AMD_INFO" ]; then
      while IFS= read -r info_line; do
        [ -n "$info_line" ] && info "  [INFO] $info_line"
      done < <(printf '%b' "$CACHED_AMD_INFO")
    fi
  elif [ "$VERBOSE" -eq 1 ]; then
    info "-- Gate 8: [SKIP] (stop-code filter excludes 0x4E) --"
  fi

  if gate_enabled 9; then
    set_gate 9 "7125237" "0x5D"
    info "-- Gate 9 (cluster): AMD nodes present --"
    if [ "${CACHED_CPU_VENDOR_AMD:-0}" -gt 0 ]; then
      # v0.17.0 (F3): this is a pointer to the per-VM check below
      # (warn_strict() at Gate 9's per-VM block), not itself a finding --
      # every AMD fleet has AMD nodes by definition, so warn() here meant NO
      # AMD fleet could ever reach a clean cnv-mtv-plan-gate.sh verdict, even
      # one where every VM had arch-capabilities correctly disabled. The real
      # risk signal is unaffected: the per-VM warn_strict() below still
      # fires/fails exactly as before for a VM that is actually non-compliant.
      info "AMD worker nodes detected -- per-VM arch-capabilities check follows below"
    else
      if _require_evidence "${CACHED_NODES_JSON_ERR:-0}" "worker node list"; then
        ok "no AMD worker nodes detected (arch-capabilities check not required)"
      fi
    fi
  elif [ "$VERBOSE" -eq 1 ]; then
    info "-- Gate 9 (cluster): [SKIP] (stop-code filter excludes 0x5D) --"
  fi

  if gate_enabled 12; then
    set_gate 12 "" "0x101"
    info "-- Gate 12: TSC frequency consistency across nodes --"
    if [ -n "$CACHED_TSC_LABELS" ]; then
      tsc_values=$(echo "$CACHED_TSC_LABELS" | cut -d= -f2 | sort -u)
      tsc_count=$(echo "$tsc_values" | wc -l)
      if [ "$tsc_count" -gt 1 ]; then
        warn "TSC frequency mismatch across nodes (found $tsc_count distinct values) -- live-migration 0x101 risk"
        [ "$JSON_MODE" = "" ] && echo "$CACHED_TSC_LABELS" | head -5 | while read -r line; do echo "    $line"; done
      else
        ok "TSC frequency consistent across labeled nodes"
      fi
    else
      # R-14 (v0.19.0 unified review U-07): absent TSC labels used to be an
      # unscored `info` line. That is the ROOT CAUSE of the Gate 6 finding
      # (R-03/U-02): KubeVirt refuses to live-migrate a VMI with HyperV
      # Reenlightenment when no node exposes a tsc-frequency scheduling label,
      # reporting LiveMigratable=False / NoTSCFrequencyNotLiveMigratable.
      # Measured live, that blocked 19 of 20 running Windows VMIs across two
      # clusters -- while this gate printed the cause on screen with no severity
      # and contributed nothing to the verdict.
      #
      # Scored only when it actually bites: Reenlightenment ships in the stock
      # Red Hat Windows templates, so on a Windows fleet this is close to
      # universal, but a cluster with no such VM has no exposure and must not be
      # warned. Counted over the audit's own Windows-VM population so the
      # severity and the explanation agree.
      _g12_reenl=0
      if [ -n "${CACHED_SCOPE_VM_JSON:-}" ]; then
        _g12_reenl=$(echo "$CACHED_SCOPE_VM_JSON" | jq "[.items[]
          | $_WIN_VM_JQ_SELECT
          | select(.spec.template.spec.domain.features.hyperv.reenlightenment != null)] | length" 2>/dev/null)
      fi
      if [ "${_g12_reenl:-0}" -gt 0 ]; then
        warn "no tsc-frequency scheduling labels on any worker node, and ${_g12_reenl} Windows VM(s) in scope use HyperV Reenlightenment -- KubeVirt reports those VMIs LiveMigratable=False (NoTSCFrequencyNotLiveMigratable), so a node drain cannot migrate them. See Gate 6 for the per-VM consequence: with evictionStrategy=LiveMigrate the pod is force-deleted after the drain timeout (dirty shutdown). Fix by exposing TSC frequency on the nodes, or set evictionStrategy=LiveMigrateIfPossible"
      else
        info "  no TSC frequency labels found on worker nodes (tsc-frequency scheduling labels not set; no in-scope Windows VM uses HyperV Reenlightenment, so no live-migration exposure)"
      fi
    fi
  elif [ "$VERBOSE" -eq 1 ]; then
    info "-- Gate 12: [SKIP] (stop-code filter excludes 0x101) --"
  fi

  # --- Gate 17: Legacy template compliance audit ---
  if gate_enabled 17; then
    set_gate 17 "7132519,7141237" "0x20001,0x7B"
    info "-- Gate 17: Legacy template compliance (openshift namespace) --"
    if [ -n "$CACHED_TEMPLATES_JSON" ] && [ "$CACHED_TEMPLATES_JSON" != '{"items":[]}' ]; then
      # M-15: `select(GENERATOR)` emits its input once per TRUTHY output of the
      # generator, so `select(.metadata.labels | keys[] | test(...))` counted a
      # template once per matching label -- a template labelled for both
      # win2k19 and win2k22 counted as two. The same applies to `.objects[]?`.
      # Verdicts were unaffected (numerator and denominator inflated together)
      # but the customer-facing counts were not: Gate 19 reported 77/140 on a
      # cluster with 20 preferences. `any(GEN; COND)` yields exactly one
      # boolean per item.
      _WIN_TMPL_FILTER='select(any(.metadata.labels // {} | keys[];
                                   test("os\\.template\\.kubevirt\\.io/win")))'
      win_templates=$(echo "$CACHED_TEMPLATES_JSON" | jq "[.items[] | $_WIN_TMPL_FILTER] | length")
      # R-12: missing ANY required feature counts, not just an absent block.
      no_hyperv_count=$(echo "$CACHED_TEMPLATES_JSON" | jq --argjson req "$REQUIRED_HYPERV_JSON" "[.items[]
        | $_WIN_TMPL_FILTER
        | select(any(.objects[]? | select(.kind == \"VirtualMachine\");
                     ((.spec.template.spec.domain.features.hyperv // {}) | keys) as \$have
                     | any(\$req[]; . as \$f | (\$have | index(\$f)) == null)))] | length")
      non_virtio_count=$(echo "$CACHED_TEMPLATES_JSON" | jq "[.items[]
        | $_WIN_TMPL_FILTER
        | select(any(.objects[]? | select(.kind == \"VirtualMachine\");
                     .spec.template.spec.domain.devices.disks[0].disk.bus != \"virtio\"))] | length")
      if [ "${no_hyperv_count:-0}" -gt 0 ]; then
        warn "${no_hyperv_count}/${win_templates} Windows template(s) missing one or more REQUIRED Hyper-V enlightenments (need: $(echo "$REQUIRED_HYPERV_JSON" | jq -r 'join(", ")')) -- 0x20001 risk; missing timer features (vpindex/synic/synictimer) also risk CLOCK_WATCHDOG_TIMEOUT (0x101) on live migration"
      fi
      if [ "${non_virtio_count:-0}" -gt 0 ]; then
        warn "${non_virtio_count}/${win_templates} Windows template(s) with non-virtio boot disk (0x7B risk)"
      fi
      if [ "${no_hyperv_count:-0}" -eq 0 ] && [ "${non_virtio_count:-0}" -eq 0 ]; then
        ok "${win_templates} Windows template(s) compliant"
      fi
    else
      if _require_evidence "${CACHED_TEMPLATES_JSON_ERR:-0}" "Windows templates"; then
        ok "no Windows templates found in openshift namespace (or templates not collected)"
      fi
    fi
  elif [ "$VERBOSE" -eq 1 ]; then
    info "-- Gate 17: [SKIP] (stop-code filter excludes 0x20001,0x7B) --"
  fi

  # --- Gate 18: InstanceType compliance audit ---
  if gate_enabled 18; then
    set_gate 18 "7136486" "0x1A"
    info "-- Gate 18: InstanceType topology compliance --"
    if [ "$INSTANCETYPE_GA" != "true" ]; then
      info "  [SKIP] InstanceType API not GA for stream $STREAM (OCP < 4.14)"
    elif [ -n "$CACHED_CLUSTER_INSTANCETYPES_JSON" ] && [ "$CACHED_CLUSTER_INSTANCETYPES_JSON" != '{"items":[]}' ]; then
      it_count=$(echo "$CACHED_CLUSTER_INSTANCETYPES_JSON" | jq '.items | length')
      high_cpu_count=$(echo "$CACHED_CLUSTER_INSTANCETYPES_JSON" | jq '[.items[] | select(.spec.cpu.guest > 64)] | length')
      if [ "${high_cpu_count:-0}" -gt 0 ]; then
        warn "${high_cpu_count}/${it_count} instancetype(s) with cpu.guest > 64 -- multiqueue risk (KCS-7136486)"
      else
        ok "${it_count} instancetype(s) checked -- topology acceptable"
      fi
    else
      if _require_evidence "${CACHED_CLUSTER_INSTANCETYPES_JSON_ERR:-0}" "cluster instancetypes"; then
        ok "no cluster instancetypes found"
      fi
    fi
  elif [ "$VERBOSE" -eq 1 ]; then
    info "-- Gate 18: [SKIP] (stop-code filter excludes 0x1A) --"
  fi

  # --- Gate 19: Preference compliance audit ---
  if gate_enabled 19; then
    set_gate 19 "7132519,7141237,7125237" "0x20001,0x7B,0x5D"
    info "-- Gate 19: Preference compliance audit --"
    if [ "$INSTANCETYPE_GA" != "true" ]; then
      info "  [SKIP] Preference API not GA for stream $STREAM (OCP < 4.14)"
    elif [ -n "$CACHED_CLUSTER_PREFERENCES_JSON" ] && [ "$CACHED_CLUSTER_PREFERENCES_JSON" != '{"items":[]}' ]; then
      # Detect Windows preferences by legacy os.template.kubevirt.io/win* label OR
      # new common-instancetypes instancetype.kubevirt.io/os-type=windows label
      # M-15: any(), not a bare generator -- see the Gate 17 comment. A
      # preference labelled for several Windows versions used to be counted
      # once per label, which is how Gate 19 reported 77/140 on a 20-preference
      # cluster. Defined once here and reused so the count and the per-check
      # filters cannot diverge.
      _WIN_PREF_FILTER='select(
        any(.metadata.labels // {} | keys[]; test("os\\.template\\.kubevirt\\.io/win"))
        or ((.metadata.labels // {} | .["instancetype.kubevirt.io/os-type"] // "") | test("^windows$";"i"))
      )'
      win_prefs=$(echo "$CACHED_CLUSTER_PREFERENCES_JSON" | jq "[.items[] | $_WIN_PREF_FILTER] | length")
      if [ "${win_prefs:-0}" -gt 0 ]; then
        # R-12: same completeness check as Gate 17 and bsod_template_checks.py.
        no_hyperv_prefs=$(echo "$CACHED_CLUSTER_PREFERENCES_JSON" | jq --argjson req "$REQUIRED_HYPERV_JSON" "[.items[]
          | $_WIN_PREF_FILTER
          | select(((.spec.features.preferredHyperv // {}) | keys) as \$have
                   | any(\$req[]; . as \$f | (\$have | index(\$f)) == null))] | length")
        non_virtio_prefs=$(echo "$CACHED_CLUSTER_PREFERENCES_JSON" | jq "[.items[]
          | $_WIN_PREF_FILTER
          | select(.spec.devices.preferredDiskBus != \"virtio\")] | length")
        # R-07 (v0.19.0 unified review U-03): the arch-capabilities sub-check is
        # gated on CACHED_CPU_VENDOR_AMD, which is derived from the WORKER NODE
        # LIST. When that list was unreadable (RBAC denial, API outage) the
        # counter stays 0 -- indistinguishable from "no AMD nodes present" --
        # so no_arch_cap_prefs stayed 0 and execution fell through to
        # `ok "N Windows preference(s) compliant"`, clearing a KCS-7125237
        # (0x5D) risk on evidence that was never collected.
        #
        # _require_evidence below already guards CACHED_CLUSTER_PREFERENCES_JSON_ERR,
        # but nothing guarded the NODE list this branch actually depends on.
        # Same class as H3's false-PASS-from-missing-evidence.
        no_arch_cap_prefs=0
        _g19_archcap_unknown=0
        if [ "${CACHED_NODES_JSON_ERR:-0}" -ne 0 ]; then
          _g19_archcap_unknown=1
          unknown "arch-capabilities compliance of ${win_prefs} Windows preference(s) cannot be assessed -- the worker node list was unreadable, so AMD-vendor presence is unknown (KCS-7125237, 0x5D)"
        elif [ "${CACHED_CPU_VENDOR_AMD:-0}" -gt 0 ]; then
          no_arch_cap_prefs=$(echo "$CACHED_CLUSTER_PREFERENCES_JSON" | jq "[.items[]
            | $_WIN_PREF_FILTER
            | select(([.spec.cpu.preferredCPUFeatures // [] | .[] | .name // .] | map(ascii_downcase) | index(\"arch-capabilities\")) == null)] | length")
        fi
        if [ "${no_hyperv_prefs:-0}" -gt 0 ]; then
          flag "${no_hyperv_prefs}/${win_prefs} Windows preference(s) missing one or more REQUIRED preferredHyperv features (need: $(echo "$REQUIRED_HYPERV_JSON" | jq -r 'join(", ")')) -- absent or partial enlightenments risk 0x20001, and missing timer features (vpindex/synic/synictimer) risk CLOCK_WATCHDOG_TIMEOUT (0x101) on live migration"
        fi
        if [ "${non_virtio_prefs:-0}" -gt 0 ]; then
          warn "${non_virtio_prefs}/${win_prefs} Windows preference(s) without preferredDiskBus=virtio (0x7B risk)"
        fi
        if [ "${no_arch_cap_prefs:-0}" -gt 0 ] && [ "${CACHED_CPU_VENDOR_AMD:-0}" -gt 0 ]; then
          warn "${no_arch_cap_prefs}/${win_prefs} Windows preference(s) missing arch-capabilities on AMD cluster (0x5D risk)"
        fi
        # R-07: only claim "compliant" when every sub-check actually ran. With
        # the node list unreadable the arch-capabilities dimension is UNKNOWN,
        # not clean, so a blanket compliance verdict would be unfounded.
        if [ "${no_hyperv_prefs:-0}" -eq 0 ] && [ "${non_virtio_prefs:-0}" -eq 0 ] \
           && [ "${no_arch_cap_prefs:-0}" -eq 0 ] && [ "$_g19_archcap_unknown" -eq 0 ]; then
          ok "${win_prefs} Windows preference(s) compliant"
        fi
      else
        ok "no Windows-labeled cluster preferences found"
      fi
    else
      if _require_evidence "${CACHED_CLUSTER_PREFERENCES_JSON_ERR:-0}" "cluster preferences"; then
        ok "no cluster preferences found"
      fi
    fi
  elif [ "$VERBOSE" -eq 1 ]; then
    info "-- Gate 19: [SKIP] (stop-code filter excludes 0x20001,0x7B,0x5D) --"
  fi

  # --- Gate 20: Prometheus alert coverage (T3) ---
  # Two shipped alerts select Windows VMs with
  #   kubevirt_vmi_info{os=~"windows|win.*"}
  # (BSODRisk_MemoryPressure, BSODRisk_EvictionBlocked). That `os` label is
  # populated from the VMI's vm.kubevirt.io/os annotation, which KubeVirt
  # inherits from spec.template.metadata.annotations. Nothing creates it: VMs
  # built from raw manifests, Terraform, or some MTV paths simply have no `os`
  # label on the metric at all, so the selector excludes them and the alerts
  # never fire for those VMs -- silently, with no error anywhere.
  #
  # That is the worst failure mode this framework has: an operator who deploys
  # the alerts and sees nothing firing cannot distinguish "healthy" from "not
  # being watched". This gate makes the blind spot visible, which is the same
  # philosophy as the UNKNOWN severity, applied to the alerting layer.
  if gate_enabled 20; then
    set_gate 20 "" ""
    info "-- Gate 20: Prometheus alert coverage (annotation-dependent alerts) --"

    # R-14: this fetch was hoisted to CACHED_SCOPE_VM_JSON (see the
    # cluster-scope prologue) so Gate 12 and Gate 20 measure the SAME VM
    # population -- if they disagreed, Gate 20's "N of M Windows VMs are
    # invisible to alerts" figure would be counting a different M than the
    # gate that produced the finding.
    _ac_all_json="$CACHED_SCOPE_VM_JSON"
    _ac_fetch_failed="$CACHED_SCOPE_VM_JSON_ERR"

    if [ "$_ac_fetch_failed" -eq 1 ] || [ -z "$_ac_all_json" ]; then
      unknown "could not list VirtualMachines to assess alert coverage -- cannot determine whether BSODRisk_MemoryPressure / BSODRisk_EvictionBlocked can see this fleet"
    else
      # Prometheus label matchers are fully anchored, so os=~"windows|win.*"
      # is ^(windows|win.*)$. Presence of the annotation is NOT sufficient --
      # a value like "server2022" is present yet still unmatched. Test the
      # regex the alert actually applies.
      _ac_total=$(echo "$_ac_all_json" | jq "[.items[] | $_WIN_VM_JQ_SELECT] | length" 2>/dev/null)
      _ac_blind_list=$(echo "$_ac_all_json" | jq -r "
        .items[] | $_WIN_VM_JQ_SELECT
        | select(((.spec.template.metadata.annotations[\"vm.kubevirt.io/os\"] // \"\")
                  | test(\"^(windows|win.*)\$\")) | not)
        | .metadata.namespace + \"/\" + .metadata.name" 2>/dev/null)
      _ac_blind=0
      [ -n "$_ac_blind_list" ] && _ac_blind=$(printf '%s\n' "$_ac_blind_list" | grep -c .)

      if [ "${_ac_total:-0}" -eq 0 ]; then
        ok "no Windows VMs in scope -- alert coverage not applicable"
      elif [ "$_ac_blind" -gt 0 ]; then
        warn "${_ac_blind}/${_ac_total} Windows VM(s) are INVISIBLE to annotation-dependent alerts: no vm.kubevirt.io/os annotation matching 'windows|win.*' on spec.template.metadata, so kubevirt_vmi_info carries no 'os' label and BSODRisk_MemoryPressure + BSODRisk_EvictionBlocked can never fire for them. Fix: annotate spec.template.metadata.annotations['vm.kubevirt.io/os']"
        _ac_shown=0
        while IFS= read -r _ac_vm; do
          [ -z "$_ac_vm" ] && continue
          if [ "$_ac_shown" -ge 10 ]; then
            info "    ... and $((_ac_blind - 10)) more"
            break
          fi
          info "    uncovered: $_ac_vm"
          _ac_shown=$((_ac_shown+1))
        done <<< "$_ac_blind_list"

        # F11 (v0.17.0): dry-run only -- prints the exact command an operator
        # would run, never executes it (this framework's established
        # no-autonomous-mutation-on-customer-clusters policy). The suggested
        # value prefers evidence already on the VM itself: the
        # vm.kubevirt.io/os LABEL (a different field from the missing
        # ANNOTATION Gate 20 is warning about -- a VM can carry one without
        # the other) or, failing that, the OS-identifying prefix of its
        # vm.kubevirt.io/template label (OCP template names follow
        # "<os-id>-<workload>-<size>", e.g. "windows2k22-server-medium" ->
        # "windows2k22", which is already a valid alert-matching value).
        # Neither is guaranteed accurate for every VM (e.g. one that only
        # matched Windows-VM detection via its hyperv feature block or its
        # name), so the generic "windows" fallback is explicitly flagged for
        # manual verification rather than presented as equally confident.
        if [ "$SUGGEST_ANNOTATE" -eq 1 ]; then
          info "  -- Gate 20: --suggest-annotate (dry-run; commands are NOT executed) --"
          # N.B. deliberately '|'-joined, NOT @tsv: bash's `read` collapses
          # consecutive tab/space/newline delimiters even under a custom
          # IFS=$'\t' (they remain classified as IFS whitespace regardless),
          # so a VM with an empty vm.kubevirt.io/os label -- the common case,
          # since that field is exactly what's being defaulted here --
          # shifted the template-label field left into the os-label
          # position, misattributing the suggestion's source. '|' is not an
          # IFS-whitespace character, so empty fields between delimiters are
          # preserved. Field values themselves cannot contain '|' (Kubernetes
          # label/name value charset excludes it).
          echo "$_ac_all_json" | jq -r "
            .items[] | $_WIN_VM_JQ_SELECT
            | select(((.spec.template.metadata.annotations[\"vm.kubevirt.io/os\"] // \"\")
                      | test(\"^(windows|win.*)\$\")) | not)
            | [
                .metadata.namespace,
                .metadata.name,
                (.metadata.labels[\"vm.kubevirt.io/os\"] // \"\"),
                ((.spec.template.metadata.labels[\"vm.kubevirt.io/template\"]
                   // .metadata.labels[\"vm.kubevirt.io/template\"] // \"\") | split(\"-\")[0])
              ] | join(\"|\")" 2>/dev/null | while IFS='|' read -r _sa_ns _sa_name _sa_os_label _sa_tmpl_prefix; do
            [ -z "$_sa_name" ] && continue
            # N24 (v0.17.0, F11 live-cluster validation on cluster-f5rfz):
            # `oc annotate vm ...` -- what an earlier version of this
            # suggestion printed -- only ever patches the VM's own
            # TOP-LEVEL metadata.annotations. Gate 20's check (and the
            # underlying alert-label problem) is about
            # spec.template.metadata.annotations, a completely different
            # field that becomes the running VMI's labels; `oc annotate`
            # has no syntax for a nested path. Applying the old suggested
            # command against a real coverage gap on cluster-f5rfz left the
            # VM listed as uncovered afterward -- a syntactically valid but
            # functionally no-op suggestion. `oc patch --type=merge` on
            # spec.template.metadata.annotations is required instead; merge
            # semantics add/overwrite only the named key, preserving any
            # other annotations already there (e.g.
            # kubevirt.io/pci-topology-version). Factored into
            # _gate20_suggest_cmd (Issue I) so the per-VM finding below can
            # reach the identical logic.
            _gate20_suggest_cmd "$_sa_ns" "$_sa_name" "$_sa_os_label" "$_sa_tmpl_prefix"
          done
        fi
      else
        ok "all ${_ac_total} Windows VM(s) carry a vm.kubevirt.io/os annotation the alerts can select"
      fi
    fi

    # Node-label exposure gates BSODRisk_AMDNodeRequiresMicrocodeVerification
    # and BSODRisk_HeterogeneousCPUMigration, both of which read
    # kube_node_labels. kube-state-metrics only emits label_* series for
    # allowlisted labels; OCP 4.14+ defaults to nodes=[*], but that default can
    # be overridden in the cluster-monitoring-config ConfigMap.
    # The determinant is the OCP version: 4.14+ ships nodes=[*] as the CMO
    # default, and there is no supported user-facing knob to narrow it. On
    # older releases node labels are NOT exported unless configured, so both
    # alerts are blind out of the box.
    _ac_ocp_minor=""
    case "$OCP_VER" in
      4.*) _ac_ocp_minor="${OCP_VER#4.}" ;;
    esac
    if [ -z "$_ac_ocp_minor" ] || ! [ "$_ac_ocp_minor" -eq "$_ac_ocp_minor" ] 2>/dev/null; then
      unknown "OCP version could not be determined -- cannot tell whether kube-state-metrics exports node labels; if it does not, BSODRisk_AMDNodeRequiresMicrocodeVerification and BSODRisk_HeterogeneousCPUMigration never fire. Verify with: kube_node_labels{label_cpu_vendor_node_kubevirt_io_amd=\"true\"}"
    elif [ "$_ac_ocp_minor" -lt 14 ]; then
      warn "OCP ${OCP_VER} predates the kube-state-metrics nodes=[*] label default (4.14+) -- kube_node_labels likely carries no label_cpu_vendor_node_kubevirt_io_* series, so BSODRisk_AMDNodeRequiresMicrocodeVerification and BSODRisk_HeterogeneousCPUMigration silently never fire. Add the node label allowlist to cluster-monitoring-config"
    else
      ok "OCP ${OCP_VER} exports node labels by default (kube-state-metrics nodes=[*]) -- node-label-dependent alerts can evaluate"
    fi
  elif [ "$VERBOSE" -eq 1 ]; then
    info "-- Gate 20: [SKIP] --"
  fi

  info "============ END CLUSTER-SCOPE CHECKS ============"

  # Capture cluster-scope findings for JSON
  JSON_FINDINGS_CLUSTER=("${CURRENT_VM_FINDINGS[@]}")
  CURRENT_VM_FINDINGS=()
  CURRENT_VM_SEV=(); CURRENT_VM_MSG=()
fi

# If --cluster-scope-only, skip the per-VM loop and exit with FAIL semantics.
if [ "$CLUSTER_SCOPE_ONLY" -eq 1 ]; then
  if [ "$JSON_MODE" = "" ]; then
    echo
    echo "=============================================================="
    if [ "$FINDINGS" -eq 0 ] && [ "$WARNINGS" -eq 0 ] && [ "$UNKNOWNS" -eq 0 ]; then
      green " Cluster-scope: no findings."
    elif [ "$FINDINGS" -eq 0 ]; then
      amber " Cluster-scope: no hard failures. $WARNINGS warning(s)."
    else
      red " Cluster-scope: $FINDINGS hard finding(s)."
      [ "$WARNINGS" -gt 0 ] && amber " $WARNINGS additional warning(s)."
    fi
    if [ "$UNKNOWNS" -gt 0 ]; then
      echo " $UNKNOWNS check(s) UNASSESSED (missing evidence) -- not passes."
    fi
    echo "=============================================================="
  elif [ "$JSON_MODE" = "doc" ]; then
    # Same --slurpfile-over-argv fix as the main JSON_MODE=doc block below
    # (ARG_MAX guard, 2026-08-05) -- this path has no per-VM findings
    # (`vms: []` always), but cluster-scope findings are still an unbounded
    # list under `oc` control, not this script's, so it gets the same
    # file-based treatment rather than assuming it stays small forever.
    _cso_tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/bsod-audit-cso.XXXXXX")
    printf '%s' "$(printf '%s\n' "${JSON_FINDINGS_CLUSTER[@]:-}" | jq -s '.')" > "$_cso_tmpdir/cluster_findings.json"
    jq -n \
      --arg version "1.0" \
      --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg ocp_version "$OCP_VER" \
      --arg stream "$STREAM" \
      --slurpfile _cluster_findings "$_cso_tmpdir/cluster_findings.json" \
      --argjson fail "$FINDINGS" \
      --argjson warn "$WARNINGS" \
      --argjson unknown "$UNKNOWNS" \
      '{version: $version, timestamp: $timestamp, ocp_version: $ocp_version, stream: $stream, cluster_scope: {findings: $_cluster_findings[0], fail_count: $fail, warn_count: $warn, unknown_count: $unknown}, vms: [], summary: {total_vms: 0, fail: $fail, warn: $warn, unknown: $unknown, pass: 0, evidence_completeness_pct: 0}}'
    rm -rf "$_cso_tmpdir"
  elif [ "$JSON_MODE" = "ndjson" ]; then
    jq -c -n --argjson fail "$FINDINGS" --argjson warn "$WARNINGS" --argjson unknown "$UNKNOWNS" \
      '{type: "summary", total_vms: 0, fail: $fail, warn: $warn, unknown: $unknown, pass: 0, evidence_completeness_pct: 0}'
  fi
  if [ "$FINDINGS" -gt 0 ]; then
    exit 1
  fi
  # R-08 (v0.19.0 unified review U-04): --fail-on-unknown must be enforced on
  # THIS exit path too. The global enforcement lives at the very bottom of the
  # script, which --cluster-scope-only never reaches -- so the flag parsed
  # cleanly, appeared in --help, and silently did nothing in this mode.
  #
  # That combination is not hypothetical: cnv-mtv-plan-gate.sh runs exactly
  # `$BSOD_CHECK_CMD $STRICT_FLAG --cluster-scope-only "$TARGET_NS"`, so an
  # unattended migration gate asking to block on unassessed checks was silently
  # not blocking on the cluster-scope half of its own audit.
  if [ "$FAIL_ON_UNKNOWN" -eq 1 ] && [ "$UNKNOWNS" -gt 0 ]; then
    if [ "$JSON_MODE" = "" ]; then
      red "EXIT 1: --fail-on-unknown set and $UNKNOWNS cluster-scope check(s) could not be evaluated."
      red "        The cluster was NOT assessed as safe -- it was not fully assessed at all."
    fi
    exit 1
  fi
  exit 0
fi

# --- Per-namespace VM loop ---
TOTAL_VMS=0
TOTAL_PASS=0
_VM_PROGRESS=0

for current_ns in "${NAMESPACES[@]}"; do
  CURRENT_VM_NS="$current_ns"

  # Batch-fetch all VMs in namespace (eliminates per-VM oc get calls)
  local_selector=""
  [ -n "$LABEL_SELECTOR" ] && local_selector="-l $LABEL_SELECTOR"

  if [ -n "$VM" ]; then
    vms="$VM"
    # Single VM mode: fetch just this one
    CACHED_VM_LIST_JSON=$(timeout 120 oc get vm "$VM" -n "$current_ns" -o json 2>/dev/null || echo "")
    if [ -z "$CACHED_VM_LIST_JSON" ]; then
      set_gate 0
      # N21 (v0.16.0): this is "we could not look", not "we found a risk" --
      # use unknown() (UNKN), not flag() (FAIL), matching the UNKNOWN severity
      # contract's own stated philosophy.
      unknown "cannot read VM $VM in namespace $current_ns"
      continue
    fi
    # Wrap single VM in items array for consistent handling
    CACHED_VM_LIST_JSON=$(echo "$CACHED_VM_LIST_JSON" | jq '{items: [.]}')
  elif [ "$ALL_VMS" -eq 1 ]; then
    # H3 follow-up (v0.16.0 #1): this namespace-scoped fetch previously used
    # the raw `oc get ... 2>/dev/null || echo '{"items":[]}'` pattern H3
    # eliminated everywhere else -- an RBAC-restricted or unreachable
    # namespace silently reported "0 VMs found" and moved on, indistinguishable
    # from a namespace that genuinely has none. _oc_fetch/_require_evidence
    # (below) make that acquisition failure visible instead of swallowing it.
    # shellcheck disable=SC2086
    _oc_fetch CACHED_VM_LIST_JSON "VMs in namespace $current_ns" -- get vm -n "$current_ns" $local_selector
    vms=$(echo "$CACHED_VM_LIST_JSON" | jq -r '.items[].metadata.name')
  else
    # shellcheck disable=SC2086
    _oc_fetch CACHED_VM_LIST_JSON "VMs in namespace $current_ns" -- get vm -n "$current_ns" $local_selector
    vms=$(echo "$CACHED_VM_LIST_JSON" | jq -r ".items[] | $_WIN_VM_JQ_SELECT | .metadata.name")
  fi

  if [ -z "$vms" ]; then
    if [ "${CACHED_VM_LIST_JSON_ERR:-0}" = "1" ]; then
      # The VM list itself could not be read -- "0 VMs" here means "we could
      # not look", not "there are none". Surface it as UNKNOWN and move on
      # rather than silently treating the namespace as empty (H3 follow-up).
      set_gate 0
      unknown "VM list for namespace $current_ns could not be read -- this namespace could not be audited (see ACQUISITION ERRORS above)"
      continue
    fi
    if [ "${#NAMESPACES[@]}" -eq 1 ]; then
      red "No VMs found in namespace $current_ns (use --all-vms to include non-Windows VMs)"
      exit 1
    fi
    continue
  fi

  # Pre-index VMs by name for O(1) lookups (avoids O(N^2) scan at scale)
  CACHED_VM_INDEX=$(echo "$CACHED_VM_LIST_JSON" | jq '[.items[] | {key: .metadata.name, value: .}] | from_entries')

  # Batch-fetch VMIs for this namespace (eliminates per-VM oc get vmi calls).
  # H3 follow-up (v0.16.0 #1): converted to _oc_fetch so CACHED_VMI_LIST_JSON_ERR
  # distinguishes "no VMIs in this namespace" from "the VMI list could not be
  # read" (e.g. RBAC allows `get virtualmachines` but not
  # `get virtualmachineinstances`). Every downstream consumer of
  # CACHED_VMI_INDEX below must treat a missing entry as ambiguous (could be a
  # stopped VM, or could be evidence we never got to see) whenever
  # CACHED_VMI_LIST_JSON_ERR=1, and use _require_evidence before concluding OK.
  CACHED_VMI_LIST_JSON=""
  _oc_fetch CACHED_VMI_LIST_JSON "VMIs in namespace $current_ns" -- get vmi -n "$current_ns"
  CACHED_VMI_INDEX=$(echo "$CACHED_VMI_LIST_JSON" | jq '[.items[] | {key: .metadata.name, value: .}] | from_entries')

  # M-10: namespaced preferences/instancetypes for this namespace. A VM selects
  # between the namespaced and cluster-scoped object via spec.preference.kind /
  # spec.instancetype.kind; resolution below is kind-aware and must be able to
  # reach both. Requires read on virtualmachinepreferences/-instancetypes (see
  # tekton/rbac.yaml) -- an empty index is indistinguishable from "none exist",
  # which is why a kind-aware miss is reported explicitly rather than ignored.
  CACHED_NS_PREFERENCES_INDEX='{}'
  CACHED_NS_INSTANCETYPES_INDEX='{}'
  if [ "$INSTANCETYPE_GA" = "true" ]; then
    CACHED_NS_PREFERENCES_INDEX=$(timeout 60 oc get virtualmachinepreference -n "$current_ns" -o json 2>/dev/null \
      | jq '[.items[] | {key: .metadata.name, value: .}] | from_entries' 2>/dev/null || echo '{}')
    [ -z "$CACHED_NS_PREFERENCES_INDEX" ] && CACHED_NS_PREFERENCES_INDEX='{}'
    CACHED_NS_INSTANCETYPES_INDEX=$(timeout 60 oc get virtualmachineinstancetype -n "$current_ns" -o json 2>/dev/null \
      | jq '[.items[] | {key: .metadata.name, value: .}] | from_entries' 2>/dev/null || echo '{}')
    [ -z "$CACHED_NS_INSTANCETYPES_INDEX" ] && CACHED_NS_INSTANCETYPES_INDEX='{}'
  fi

  # Initialize namespace counters
  NS_VM_COUNT["$current_ns"]=0
  NS_FAIL_COUNT["$current_ns"]=0
  NS_WARN_COUNT["$current_ns"]=0
  NS_UNKNOWN_COUNT["$current_ns"]=0
  NS_PASS_COUNT["$current_ns"]=0

  _ns_vm_total=$(echo "$vms" | wc -w)

  for v in $vms; do
    _IN_VM_LOOP=1
    _VM_PROGRESS=$((_VM_PROGRESS+1))
    CURRENT_VM_NAME="$v"
    CURRENT_VM_FINDINGS=()
    CURRENT_VM_SEV=(); CURRENT_VM_MSG=()
    [ "${RS_CONFIG_LOADED:-0}" -eq 1 ] && rs_reset
    local_findings_before=$FINDINGS
    local_passes_before=$PASSES
    local_warnings_before=$WARNINGS
    local_unknowns_before=$UNKNOWNS

    # Progress indicator on stderr (not captured in report output)
    if [ "$JSON_MODE" = "" ] && [ -t 2 ]; then
      printf '\r\033[K  [%d] Checking %s/%s...' "$_VM_PROGRESS" "$current_ns" "$v" >&2
    fi

    if [ "$SUMMARY_ONLY" -eq 0 ]; then
      info ""
      info "############# VM: $current_ns/$v #############"
    fi

    # O(1) lookup from pre-indexed VM object
    spec=$(echo "$CACHED_VM_INDEX" | jq --arg n "$v" '.[$n]')
    if [ -z "$spec" ] || [ "$spec" = "null" ]; then
      set_gate 0
      flag "cannot read VM $v"
      continue
    fi

    # Instancetype/preference resolution for VMs with sparse specs (OCP 4.19+).
    # M-10: `kind` is read alongside `name`. It selects between the namespaced
    # (VirtualMachinePreference) and cluster-scoped (VirtualMachineClusterPreference)
    # object. Previously only `name` was read and the lookup always hit the
    # CLUSTER index -- so a VM using a namespaced preference either failed to
    # resolve, or, if a cluster preference happened to share the name, resolved
    # against the wrong object and the gates reported on a config the VM does
    # not have. KubeVirt defaults an omitted kind to the cluster-scoped form.
    # N13: `kind` is read alongside `name` for instancetype too, mirroring the
    # preference fix above -- an omitted kind defaults to the cluster-scoped
    # VirtualMachineClusterInstancetype form.
    IFS=$'\t' read -r vm_it_name vm_it_kind vm_pref_name vm_pref_kind < <(echo "$spec" | jq -r '
      [(.spec.instancetype.name // ""), (.spec.instancetype.kind // ""),
       (.spec.preference.name // ""), (.spec.preference.kind // "")] | @tsv')
    # shellcheck disable=SC2034  # reserved for summary output
    RESOLVED_FROM_VMI=0

    if [ -n "$vm_it_name" ] || [ -n "$vm_pref_name" ]; then
      if [ "$SPEC_EXPANSION" = "false" ]; then
        # On OCP 4.19+, spec is sparse; prefer VMI (fully expanded at admission)
        vmi_spec=$(echo "$CACHED_VMI_INDEX" | jq --arg n "$v" '.[$n] // empty' 2>/dev/null)
        if [ -n "$vmi_spec" ] && [ "$vmi_spec" != "null" ]; then
          # Merge VMI domain into spec for downstream gates
          spec=$(echo "$spec" | jq --argjson vmi "$vmi_spec" '
            .spec.template.spec.domain = ($vmi.spec.domain // .spec.template.spec.domain)')
          # shellcheck disable=SC2034
          RESOLVED_FROM_VMI=1
        else
          # VMI not running; resolve from cached instancetypes/preferences.
          # Preference is resolved FIRST (even though instancetype is applied
          # second) because the preference's `cpu.preferredCPUTopology` (if
          # set) determines HOW the instancetype's `cpu.guest` count is
          # projected into sockets/cores/threads below.
          pref_spec="{}"
          if [ -n "$vm_pref_name" ]; then
            case "$vm_pref_kind" in
              # Namespaced kind, in either the singular or plural spelling
              # KubeVirt accepts.
              VirtualMachinePreference|virtualmachinepreference|virtualmachinepreferences)
                _pref_index="$CACHED_NS_PREFERENCES_INDEX"
                _pref_scope="namespaced" ;;
              *)
                _pref_index="${CACHED_CLUSTER_PREFERENCES_INDEX:-{\}}"
                _pref_scope="cluster" ;;
            esac
            pref_spec=$(echo "$_pref_index" | jq --arg n "$vm_pref_name" '.[$n].spec // {}')
            if [ -z "$pref_spec" ] || [ "$pref_spec" = "null" ] || [ "$pref_spec" = "{}" ]; then
              # Do not fall through silently: the VM is stopped AND its
              # preference is unreadable, so nothing downstream reflects the
              # VM's real domain. Gates that follow will see a sparse spec.
              set_gate 0
              unknown "VM $v references ${_pref_scope} preference '$vm_pref_name' which could not be read (VM is stopped, so there is no VMI to expand it) -- the gates below evaluate a sparse spec and cannot rule out risks the preference would supply. Grant read on virtualmachinepreferences/virtualmachineclusterpreferences, or start the VM"
              pref_spec="{}"
            fi
          fi

          # N13: instancetype resolution. Previously `vm_it_name` was
          # extracted but never resolved, so a stopped VM referencing an
          # instancetype always fell through to the sparse spec's cpu/memory
          # defaults (sockets=1, cores=1, threads=1) regardless of the
          # instancetype's actual cpu.guest -- Gate 14 (socket cap) and the
          # multiqueue-relevant gates silently evaluated the wrong vCPU
          # count.
          if [ -n "$vm_it_name" ]; then
            case "$vm_it_kind" in
              # Namespaced kind, in either the singular or plural spelling
              # KubeVirt accepts.
              VirtualMachineInstancetype|virtualmachineinstancetype|virtualmachineinstancetypes)
                _it_index="$CACHED_NS_INSTANCETYPES_INDEX"
                _it_scope="namespaced" ;;
              *)
                _it_index="${CACHED_CLUSTER_INSTANCETYPES_INDEX:-{\}}"
                _it_scope="cluster" ;;
            esac
            it_spec=$(echo "$_it_index" | jq --arg n "$vm_it_name" '.[$n].spec // {}')
            if [ -z "$it_spec" ] || [ "$it_spec" = "null" ] || [ "$it_spec" = "{}" ]; then
              # Do not fall through silently: the VM is stopped AND its
              # instancetype is unreadable, so nothing downstream reflects
              # the VM's real vCPU/memory topology. Gates that follow will
              # see a sparse spec's cpu/memory defaults.
              set_gate 0
              unknown "VM $v references ${_it_scope} instancetype '$vm_it_name' which could not be read (VM is stopped, so there is no VMI to expand it) -- the gates below evaluate a sparse spec's default vCPU/memory topology and cannot rule out risks the instancetype's real cpu.guest/memory.guest would supply. Grant read on virtualmachineinstancetypes/virtualmachineclusterinstancetypes, or start the VM"
            fi
            if [ -n "$it_spec" ] && [ "$it_spec" != "null" ] && [ "$it_spec" != "{}" ]; then
              # Apply instancetype-resolved topology to empty fields. KubeVirt
              # projects cpu.guest into sockets/cores/threads per the
              # preference's cpu.preferredCPUTopology -- default "sockets"
              # (cpu.guest vCPUs each become a socket) absent an explicit
              # preference, so this is the field Gate 14's 2-socket Desktop
              # cap actually depends on. memory.guest maps directly to
              # domain.memory.guest.
              spec=$(echo "$spec" | jq --argjson it "$it_spec" --argjson pref "$pref_spec" '
                (($pref.cpu.preferredCPUTopology // "sockets") | ascii_downcase) as $topo |
                if (.spec.template.spec.domain.cpu // {} | length) == 0 and ($it.cpu.guest // null) != null then
                  .spec.template.spec.domain.cpu =
                    (if $topo == "cores" then {sockets: 1, cores: $it.cpu.guest, threads: 1}
                     elif $topo == "threads" then {sockets: 1, cores: 1, threads: $it.cpu.guest}
                     else {sockets: $it.cpu.guest, cores: 1, threads: 1} end)
                else . end
                | if (.spec.template.spec.domain.memory // {} | length) == 0 and ($it.memory.guest // null) != null then
                  .spec.template.spec.domain.memory.guest = $it.memory.guest
                else . end')
            fi
          fi

          if [ -n "$pref_spec" ] && [ "$pref_spec" != "null" ] && [ "$pref_spec" != "{}" ]; then
              # Apply preference defaults to empty fields
              spec=$(echo "$spec" | jq --argjson pref "$pref_spec" '
                if (.spec.template.spec.domain.features.hyperv // null) == null and ($pref.features.preferredHyperv // null) != null then
                  .spec.template.spec.domain.features.hyperv = $pref.features.preferredHyperv
                else . end
                | if (.spec.template.spec.domain.machine.type // "") == "" and ($pref.machine.preferredMachineType // "") != "" then
                  .spec.template.spec.domain.machine.type = $pref.machine.preferredMachineType
                else . end
                | if (.spec.template.spec.domain.devices.disks // [] | length) > 0 then
                  .spec.template.spec.domain.devices.disks = [.spec.template.spec.domain.devices.disks[] |
                    if (.disk.bus // "unset") == "unset" and ($pref.devices.preferredDiskBus // "") != "" then
                      .disk.bus = $pref.devices.preferredDiskBus
                    else . end]
                else . end')
          fi
        fi
      fi
    fi

    # H3 follow-up (v0.16.0 #1): whether the vCPU/socket topology about to be
    # extracted below is confirmed by a readable source, or is a sparse-spec
    # default that depended on the VMI list and that list could not be read.
    # Only ambiguous when ALL of: OCP 4.19+ sparse-spec cluster, this VM
    # references an instancetype/preference (so topology isn't in its own raw
    # spec), the VMI merge above did NOT resolve it (RESOLVED_FROM_VMI=0 --
    # true both for a genuinely stopped VM and for "we couldn't tell"), AND
    # the VMI list fetch itself failed. Gates 10/14 must not report an
    # OK/resolved vCPU count derived from this ambiguous topology.
    _TOPOLOGY_UNCONFIRMED=0
    if [ "$SPEC_EXPANSION" = "false" ] && [ "$RESOLVED_FROM_VMI" -eq 0 ] \
       && { [ -n "$vm_it_name" ] || [ -n "$vm_pref_name" ]; } \
       && [ "${CACHED_VMI_LIST_JSON_ERR:-0}" = "1" ]; then
      _TOPOLOGY_UNCONFIRMED=1
    fi

    # --- Batch field extraction (1 jq fork replaces ~20 per-gate forks) ---
    # Each line maps to _F[index]; see comments for field semantics.
    # shellcheck disable=SC2034,SC2207
    mapfile -t _F < <(echo "$spec" | jq -r '
      .spec.template as $t | $t.spec.domain as $d |
      ($d.cpu // {}) as $cpu | ($d.devices // {}) as $dev |
      ($t.metadata.annotations // {}) as $ann |
      # R-11: the Python vm_spec.annotations map is {**meta, **tmeta}; the
      # Gate 7 migration-source dimension must see the same set, and
      # MTV/Forklift commonly annotate the top-level VM, not the template.
      ((.metadata.annotations // {}) + ($t.metadata.annotations // {})) as $allann |
      ($t.metadata.labels // {}) as $lbl |

      # [0] OS hint
      ($ann["vm.kubevirt.io/os"] // $lbl["vm.kubevirt.io/template"] // "unknown"),
      # [1] machine type
      ($d.machine.type // "default(q35)"),
      # [2] CPU model
      ($cpu.model // "unset(host-model)"),
      # [3] hyperv present/absent
      (if $d.features.hyperv != null then "present" else "absent" end),
      # [4] eviction strategy
      ($t.spec.evictionStrategy // "unset"),
      # [5] WSL/nested-virt annotation hit count
      ($ann | to_entries | map(select((.key+.value)|test("wsl|nested|hyper-?v";"i"))) | length),
      # [6] arch-capabilities disabled count
      ([$cpu.features // [] | .[] | select(.name == "arch-capabilities" and .policy == "disable")] | length),
      # [7] virtio-blk disk count
      ([$dev.disks[]? | select((.disk.bus // "") == "virtio")] | length),
      # [8] blockMultiQueue explicit value
      (if $dev.blockMultiQueue == true then "true" elif $dev.blockMultiQueue == false then "false" else "unset" end),
      # [9] sockets  [10] cores  [11] threads
      ($cpu.sockets // 1), ($cpu.cores // 1), ($cpu.threads // 1),
      # [12] vcpu total
      (($cpu.cores // 1) * ($cpu.sockets // 1) * ($cpu.threads // 1)),
      # [13] e1000 NIC count
      ([$dev.interfaces[]? | select((.model//"")|test("e1000";"i"))] | length),
      # [14] PVC/DataVolume references (comma-separated)
      ([.spec.template.spec.volumes[]? | .persistentVolumeClaim.claimName // .dataVolume.name // empty] | unique | join(", ")),
      # [15] boot disks (pipe-separated name=bus)
      ([$dev.disks[]? | select((.bootOrder // 99) == 1 or .name=="rootdisk" or .name=="containerdisk") | "\(.name)=\(.disk.bus // .cdrom.bus // "unset")"] | join("|")),
      # [16] all-disk detail listing (pipe-separated, for Gate 1 fallback display)
      ([$dev.disks[]? | "  \(.name): bus=\(.disk.bus // .cdrom.bus // "unset")"] | join("|")),
      # [17] NIC detail listing (pipe-separated, for Gate 3 display)
      ([$dev.interfaces[]? | "  \(.name): model=\(.model // "default")"] | join("|")),
      # [18] virtio-win driver source attached? (Gate 21 / master remediation
      # plan Phase 4): matches a volume whose containerDisk.image OR own
      # name contains "virtio-win"/"virtiowin" (case-insensitive, hyphen
      # optional) -- image NAME match, not a specific registry host/tag/
      # digest, so this also recognizes customer-mirrored copies. Mirrors
      # insights-rules/parsers/vm_spec.py::_VIRTIO_WIN_SOURCE_RE exactly.
      ([$t.spec.volumes[]? | select(((.containerDisk.image // "") + " " + (.name // "")) | test("virtio.?win";"i"))] | length > 0 | tostring),
      # [19] migration-source annotation count (R-11 / KCS-7132519).
      # Gate 7 previously tested ONLY the nested/WSL hint, collapsing two
      # materially different risk states into one WARN. KCS-7132519 is
      # specifically about VMware-MIGRATED guests running WSL/Hyper-V, so the
      # compound condition is the one the article describes. Key-only token
      # match, mirroring bsod_enlightenment_checks.py::check_wsl_nested_virt.
      ($allann | to_entries | map(select(.key | ascii_downcase
        | (contains("forklift") or contains("vmware") or contains("migration") or contains("mtv")))) | length),
      # [20] Gate 20 per-VM component (Issue I): the RAW spec.template.metadata
      # annotation value, distinct from _F[0] OS hint -- _F[0] falls back to
      # the vm.kubevirt.io/template LABEL when the annotation is absent, but
      # that fallback is exactly what makes _F[0] unsuitable here: KubeVirt
      # VMI (and therefore kubevirt_vmi_info os label that
      # BSODRisk_MemoryPressure/BSODRisk_EvictionBlocked select on) is
      # populated from the ANNOTATION only, never the template label. A VM
      # that resolves _F[0] via the label fallback still has NO annotation and
      # is therefore still alert-blind -- Gate 20 must see that distinction.
      # NOTE: this jq program is embedded in a bash single-quoted string --
      # no apostrophes/single-quotes in these comments, or bash closes the
      # string early (confirmed live: broke every downstream gate).
      ($ann["vm.kubevirt.io/os"] // ""),
      # [21] vm.kubevirt.io/os LABEL (top-level metadata, not the template
      # metadata) -- suggest-annotate first-choice suggestion source,
      # mirrors the cluster-scope block existing suggestion query below.
      (.metadata.labels["vm.kubevirt.io/os"] // ""),
      # [22] vm.kubevirt.io/template label prefix (fallback suggestion
      # source): template-level label first, then the VM own top-level
      # label -- same fallback order as the cluster-scope suggest-annotate
      # query below.
      (($lbl["vm.kubevirt.io/template"] // .metadata.labels["vm.kubevirt.io/template"] // "") | split("-")[0])
    ')
    os="${_F[0]}"
    # shellcheck disable=SC2034 # reserved for JSON VM record output
    CURRENT_VM_OS="$os"
    info "OS / template hint: $os"
    case "$os" in
      *win*|*Win*|*WIN*) : ;;
      unknown)
        set_gate 0
        warn "OS not annotated; treating as candidate Windows VM"
        ;;
      *)
        if [ "$ALL_VMS" -eq 1 ]; then
          info "  [INFO] Non-Windows VM ($os) -- skipping Windows-specific BSOD gates"
          continue
        fi
        ;;
    esac

    # ---- GATE 1: boot disk bus (INACCESSIBLE_BOOT_DEVICE 0x7B) ----
    if gate_enabled 1; then
      set_gate 1 "7141237" "0x7B"
      info "-- Gate 1: boot disk interface (0x7B risk) --"
      bootdisks="${_F[15]}"
      if [ -z "$bootdisks" ]; then
        if ! _no_output && [ -n "${_F[16]}" ]; then
          IFS='|' read -ra _disk_lines <<< "${_F[16]}"
          for _dl in "${_disk_lines[@]}"; do echo "$_dl"; done
        fi
        warn "could not isolate boot disk; review buses above (non-virtio boot disk + missing driver => 0x7B)"
      else
        IFS='|' read -ra _bd_arr <<< "$bootdisks"
        for d in "${_bd_arr[@]}"; do
          bus="${d#*=}"
          if [ "$bus" = "virtio" ]; then
            ok "boot disk $d uses virtio (driver vioscsi/viostor must be present in guest)"
          else
            warn "boot disk $d is '$bus' -- ensure virtio driver staged, or expect 0x7B after switching bus"
          fi
        done
      fi
    fi

    # ---- GATE 2: machine type (i440FX -> Q35 => 0x7B) ----
    if gate_enabled 2; then
      set_gate 2 "7141237" "0x7B"
      info "-- Gate 2: machine type (i440FX->Q35 transition => 0x7B) --"
      machine="${_F[1]}"
      info "  machine type: $machine"
      case "$machine" in
        *i440fx*) warn "i440fx detected -- valid for this guest but WARNING applies only if a future transition to Q35 is planned without driver pre-staging (KCS-7141237)" ;;
        *q35*|default*) ok "q35 (modern Windows expects q35)" ;;
        *) warn "unrecognized machine type '$machine'" ;;
      esac
    fi

    # ---- GATE 3: NIC model (virtio NetKVM; 263043 RDP fault) ----
    if gate_enabled 3; then
      set_gate 3 "263043" "0xD1"
      info "-- Gate 3: NIC model (NetKVM / legacy e1000) --"
      if ! _no_output && [ -n "${_F[17]}" ]; then
        IFS='|' read -ra _nic_lines <<< "${_F[17]}"
        for _nl in "${_nic_lines[@]}"; do echo "$_nl"; done
      fi
      nice1000="${_F[13]}"
      [ "${nice1000:-0}" -gt 0 ] && warn "e1000 NIC detected -- confirm whether intentional (raw copy mode) or VMware residue requiring migration to virtio + NetKVM >= $DRIVER_BASELINE (KCS-263043)"
    fi

    # ---- GATE 4: CPU model (live-migration 0x101/0x9C across mixed nodes) ----
    if gate_enabled 4; then
      set_gate 4 "" "0x101,0x9C"
      info "-- Gate 4: CPU model (live-migration stability) --"
      cpumodel="${_F[2]}"
      info "  cpu.model: $cpumodel"
      # Issue H (assumption-vs-evidence audit): an EXPLICIT `cpu.model:
      # host-model` carries the EXACT SAME live-migration risk as leaving
      # cpu.model unset -- both resolve to a concrete, node-specific model at
      # boot time, not a portable pinned baseline. The `unset*` pattern below
      # only ever matched the jq extraction's own default string
      # ("unset(host-model)", substituted when the field is ABSENT), so a VM
      # whose spec wrote the literal string "host-model" fell through to the
      # `*)` catch-all and was reported as an "explicit CPU model" -- the same
      # class of false reassurance as pre-fix Gates 6/8/10.
      #
      # Live-confirmed on cluster-f5rfz: the shipped `good`/`win2k22-good`
      # fixture VM (and every scenario cloned from it -- the majority of this
      # harness) sets `cpu.model: "host-model"` explicitly, and
      # `virsh dumpxml` on the running VM showed `<cpu mode='custom'>` with a
      # concrete `<model fallback='forbid'>EPYC-Milan</model>` -- resolved at
      # boot, on a cluster independently confirmed (Issue D1) to mix
      # EPYC-Rome and EPYC-Milan nodes. `fallback='forbid'` means libvirt will
      # refuse to start/migrate this exact CPU configuration on a target that
      # cannot supply it, which is precisely the 0x101/0x9C risk this gate
      # exists to catch -- and it was clearing every VM that hit this path.
      #
      # insights-rules/plugins/bsod_cpu_checks.py::check_cpu_model_live_migration
      # already excludes "host-model" from its "explicit model" PASS branch
      # (`cpu_model not in ("host-passthrough", "host-model", "")`) -- Python
      # was always correct here; this brings bash into agreement with it.
      case "$cpumodel" in
        *host-passthrough*) warn "host-passthrough blocks live migration across dissimilar CPUs" ;;
        unset*|host-model) warn "cpu.model is unset or explicitly 'host-model' -- KubeVirt/libvirt resolves this to a concrete, node-specific model at boot (confirmed live via domain XML: fallback='forbid'), not a portable pinned baseline. Pin an explicit CPU model shared across all potential migration targets for mixed-node clusters" ;;
        *) ok "explicit CPU model '$cpumodel'" ;;
      esac
    fi

    # ---- GATE 5: Hyper-V enlightenments (clock/perf bugchecks) ----
    if gate_enabled 5; then
      set_gate 5
      info "-- Gate 5: Hyper-V enlightenments --"
      if [ "${_F[3]}" = "absent" ]; then
        warn "no hyperv feature block -- Windows guests need enlightenments; use a Red Hat Windows template"
        info "         Fix: recreate VM from a Red Hat-provided Windows template, or manually add hyperv features to spec.domain.features"
      else
        ok "hyperv block present"
      fi
    fi

    # ---- GATE 6: eviction strategy (migration-as-hard-reset, dirty bugcheck) ----
    if gate_enabled 6; then
      set_gate 6
      info "-- Gate 6: eviction strategy (graceful live migrate) --"
      evict="${_F[4]}"
      info "  evictionStrategy: $evict"

      # R-03 (v0.19.0 unified review U-02): declared intent is not migration
      # reality. This gate previously returned [ OK ] for evictionStrategy=
      # LiveMigrate on the strength of the SPEC FIELD ALONE, never consulting
      # the VMI's LiveMigratable status condition -- the field KubeVirt itself
      # uses to answer this exact question.
      #
      # Measured live: 19 of 20 running Windows VMIs across two clusters had
      # evictionStrategy=LiveMigrate AND LiveMigratable=False (reason
      # NoTSCFrequencyNotLiveMigratable, from HyperV Reenlightenment in the
      # stock Red Hat Windows templates plus absent TSC node labels). Every one
      # was cleared here while BSODRisk_EvictionBlocked was concurrently FIRING
      # on nine of them -- the customer-facing gate and the shipped alert
      # returning opposite answers on the same cluster in the same hour.
      #
      # The condition is read from CACHED_VMI_INDEX, which already holds the
      # full VMI object -- no additional API call.
      _lm_status=""; _lm_reason=""; _vmi_present=0
      if [ -n "${CACHED_VMI_INDEX:-}" ]; then
        IFS=$'\t' read -r _vmi_present _lm_status _lm_reason < <(
          echo "$CACHED_VMI_INDEX" | jq -r --arg n "$v" '
            .[$n] as $vmi
            | if $vmi == null then ["0","",""]
              else ["1",
                    (($vmi.status.conditions // []) | map(select(.type=="LiveMigratable")) | .[0].status // ""),
                    (($vmi.status.conditions // []) | map(select(.type=="LiveMigratable")) | .[0].reason // "")]
              end | @tsv' 2>/dev/null)
      fi

      case "$evict" in
        LiveMigrate)
          _gate6_livemigrate_verdict "explicit"
          ;;
        LiveMigrateIfPossible)
          # Deliberately NOT warned when non-migratable: this strategy stops the
          # VM gracefully when migration is impossible, which is precisely the
          # remedy BSODRisk_EvictionBlocked's own description recommends. The
          # dirty-shutdown hazard is specific to LiveMigrate.
          if [ "${_vmi_present:-0}" = "1" ] && [ "$_lm_status" = "False" ]; then
            info "  VMI reports LiveMigratable=False${_lm_reason:+ (reason: $_lm_reason)} -- drain will stop this VM gracefully rather than migrate it"
          fi
          ok "LiveMigrateIfPossible (drain migrates if it can, otherwise stops gracefully -- no force-delete)"
          ;;
        None)
          flag "evictionStrategy=None -> node drain will force-stop the VM (dirty shutdown, not a direct BSOD trigger). [GENERAL-KNOWLEDGE] Recommend LiveMigrate or LiveMigrateIfPossible"
          info "         Fix: oc patch vm/$v -n $current_ns --type merge -p '{\"spec\":{\"template\":{\"spec\":{\"evictionStrategy\":\"LiveMigrate\"}}}}'"
          ;;
        *)
          if [ -n "$CACHED_CLUSTER_EVICTION" ]; then
            info "  cluster default: $CACHED_CLUSTER_EVICTION"
            case "$CACHED_CLUSTER_EVICTION" in
              LiveMigrate)
                # R-03: an INHERITED LiveMigrate carries exactly the same
                # force-delete hazard as an explicit one -- KubeVirt resolves
                # the default onto the VMI either way. Found live: win11-oversocket
                # has evictionStrategy unset, inherits LiveMigrate, and reports
                # LiveMigratable=False; BSODRisk_EvictionBlocked fired on it while
                # this branch still reported OK because the first version of this
                # fix only wired the condition into the explicit branch above.
                _gate6_livemigrate_verdict "inherited from cluster default"
                ;;
              LiveMigrateIfPossible)
                ok "VM inherits cluster default '$CACHED_CLUSTER_EVICTION'" ;;
              None)
                flag "VM unset and cluster default is None -> node drain will force-stop the VM. Recommend setting LiveMigrate on the VM or cluster" ;;
              *)
                warn "VM unset and cluster default is '$CACHED_CLUSTER_EVICTION' (unexpected value)" ;;
            esac
          else
            warn "evictionStrategy '$evict' and unable to determine cluster default; confirm cluster default is LiveMigrate"
          fi
          ;;
      esac
    fi

    # ---- GATE 7: WSL / nested virt (HYPERVISOR_ERROR 0x20001 ex-VMware) ----
    if gate_enabled 7; then
      set_gate 7 "7132519" "0x20001"
      info "-- Gate 7: nested-virt / WSL marker (0x20001 after VMware migration) --"
      if [ "$GATE7_ADVISORY_SHOWN" -eq 0 ]; then
        info "  ADVISORY: cluster-side annotation checks are unreliable. The guest-side"
        info "  PowerShell collector (collect-windows-guest-info.ps1) is the authoritative"
        info "  source for WSL/VBS/Hyper-V feature detection."
        GATE7_ADVISORY_SHOWN=1
      fi
      nested="${_F[5]}"
      migsrc="${_F[19]}"
      # R-11 (v0.19.0 unified review U-10): three branches, matching
      # bsod_enlightenment_checks.py::check_wsl_nested_virt and KCS-7132519.
      #
      # This gate previously tested ONE boolean (the nested/WSL hint) and had no
      # migration-source dimension at all, so it could not express the compound
      # condition the KCS is actually about. Bash and Python therefore disagreed
      # in BOTH directions and no mode reconciled them: default under-reported
      # the compound case (WARN where Python said FAIL), while --strict
      # over-reported the standalone case (FAIL where Python said WARN),
      # because warn_strict promotes unconditionally.
      if [ "${nested:-0}" -gt 0 ] && [ "${migsrc:-0}" -gt 0 ]; then
        # Compound: migrated from VMware/oVirt AND WSL/Hyper-V present. This is
        # the KCS-7132519 scenario -- hard finding regardless of --strict.
        flag "migrated guest (${migsrc} migration annotation(s)) WITH WSL/nested-virt indicators -- high 0x20001 HYPERVISOR_ERROR risk (KCS-7132519). Enable nested virtualization on the target node before starting this VM"
      elif [ "${nested:-0}" -gt 0 ]; then
        # Standalone nested/WSL, no migration evidence: real but lower risk.
        warn_strict "annotation hints at WSL/nested-virt (no migration-source annotation) -- ensure nested virtualization is enabled on the target node; 0x20001 risk (KCS-7132519)"
      else
        info "  no WSL/nested-virt annotation detected -- confirm inside the guest via PS collector"
      fi
    fi

    # ---- GATE 9 (per-VM): arch-capabilities CPU feature (UNSUPPORTED_PROCESSOR 0x5D) ----
    if gate_enabled 9; then
      set_gate 9 "7125237" "0x5D"
      info "-- Gate 9: arch-capabilities CPU feature (0x5D UNSUPPORTED_PROCESSOR) --"
      arch_cap_disabled="${_F[6]}"
      if [ "${CACHED_CPU_VENDOR_AMD:-0}" -gt 0 ] && [ "${arch_cap_disabled:-0}" -eq 0 ]; then
        warn_strict "AMD cluster + arch-capabilities NOT disabled in VM CPU features -- 0x5D risk with June 2025+ Windows Updates (KCS-7125237)"
        info "         Fix: add cpu feature {name: arch-capabilities, policy: disable} to VM spec or use a preference with preferredCpuFeatures"
      elif [ "${CACHED_NODES_JSON_ERR:-0}" = "1" ]; then
        # H3, sharpest instance: this branch is reached because
        # CACHED_CPU_VENDOR_AMD is 0 -- but when the node list was never
        # readable, 0 means "we could not look", not "no AMD nodes". Reporting
        # `arch-capabilities check passed (... amd_nodes=0)` here cleared a
        # KCS-7125237 (0x5D) risk on evidence that was never collected, and
        # printed its own blindness as the justification.
        unknown "arch-capabilities risk cannot be assessed for $v -- the worker node list was unreadable, so AMD-vendor presence is unknown (KCS-7125237, 0x5D)"
      else
        ok "arch-capabilities check passed (disabled=$arch_cap_disabled, amd_nodes=$CACHED_CPU_VENDOR_AMD)"
      fi
    fi

    # ---- GATE 10: virtio-blk multiqueue (MEMORY_MANAGEMENT 0x1A low-latency) ----
    if gate_enabled 10; then
      set_gate 10 "7136486" "0x1A"
      info "-- Gate 10: virtio-blk multiqueue (0x1A on low-latency storage) --"
      multiqueue_disks="${_F[7]}"
      explicit_multiqueue="${_F[8]}"
      vcpu_cores="${_F[12]}"
      implicit_multiqueue=false
      if [ "${multiqueue_disks:-0}" -gt 0 ] && [ "${vcpu_cores:-1}" -gt 1 ]; then
        implicit_multiqueue=true
      fi

      if [ "${multiqueue_disks:-0}" -gt 0 ] && [ "$explicit_multiqueue" = "true" ]; then
        warn_strict "virtio-blk disks with blockMultiQueue=true -- BSOD risk on low-latency storage if guest virtio-win < $MULTIQUEUE_FIX_BASELINE (KCS-7136486). Confirm guest driver via QGA/collector; workaround: set queues=1"
      elif [ "$explicit_multiqueue" = "false" ]; then
        ok "virtio-blk multiqueue explicitly disabled (blockMultiQueue: false)"
      elif [ "${multiqueue_disks:-0}" -gt 0 ] && [ "$implicit_multiqueue" = "true" ]; then
        # R-06 (v0.19.0 unified review U-05): this previously read
        #   warn "... KubeVirt implicitly enables multiqueue ..."
        # asserting a platform behaviour that does not exist. `oc explain
        # vmi.spec.domain.devices.blockMultiQueue` documents "Defaults to
        # false", and live `virsh dumpxml` on CNV 4.18.8 and 4.21.13 showed NO
        # queues attribute on multi-vCPU VMs whenever blockMultiQueue was unset
        # -- versus queues='8' when explicitly true. The inference WARNed on
        # 26/33 and 19/26 VMs across two live clusters: the fleet's
        # second-most-common finding, and entirely spurious.
        #
        # The cluster API cannot read the running domain XML (that needs an
        # exec into the virt-launcher pod), so the honest cluster-side verdict
        # is UNKNOWN. The Python analyzer resolves it definitively from the
        # domain.xml that gather_virt_bsod_runtime already collects.
        unknown "virtio-blk disks + multi-vCPU ($vcpu_cores vCPUs) with blockMultiQueue unset -- KubeVirt's default is false, but the cluster API cannot confirm the RUNNING queue configuration. Not a detected risk and not a pass. Confirm via must-gather runtime domain XML (analyze.py) or: oc exec -n $current_ns virt-launcher-<pod> -c compute -- virsh dumpxml 1 | grep queues= (KCS-7136486)"
      elif [ "${multiqueue_disks:-0}" -gt 0 ] && [ "$_TOPOLOGY_UNCONFIRMED" -eq 1 ]; then
        # H3 follow-up (v0.16.0 #1): blockMultiQueue is unset, so the verdict
        # hinges on vcpu_cores -- but that count came from a sparse spec whose
        # VMI/instancetype expansion we could not confirm because the VMI
        # list was unreadable. Reporting "single vCPU (no risk)" here would be
        # the same false-PASS-from-missing-evidence class H3 fixed elsewhere.
        _require_evidence "${CACHED_VMI_LIST_JSON_ERR:-0}" "VMI status for $v (needed to confirm vCPU topology for the implicit-multiqueue check)"
      elif [ "${multiqueue_disks:-0}" -gt 0 ]; then
        ok "virtio-blk disks present, single vCPU (no multiqueue risk)"
      else
        ok "no virtio-blk disks detected"
      fi
    fi

    # Slice VMI from cached list (1 fork: existence + guest OS info)
    IFS=$'\t' read -r _vmi_found _vmi_guest_os < <(echo "$CACHED_VMI_INDEX" | jq -r --arg n "$v" '
      .[$n] as $vmi | if $vmi then ["yes", ($vmi.status.guestOSInfo.id // "")] | @tsv
      else ["no", ""] | @tsv end')
    vmi_exists=""
    [ "$_vmi_found" = "yes" ] && vmi_exists="yes"

    # ---- GATE 11: Storage latency checklist (advisory; KCS-7132512) ----
    if gate_enabled 11; then
      set_gate 11 "7132512" "0x1A"
      info "-- Gate 11: storage latency checklist (advisory) --"
      if [ -n "$vmi_exists" ]; then
        # _F[14] is a comma-joined list of PVC claim names / DataVolume
        # names -- NOT StorageClasses. The label printed below has always been
        # right; only this local was misnamed.
        pvc_refs="${_F[14]}"
        if [ -n "$pvc_refs" ]; then
          info "  PVC/DataVolume references: $pvc_refs"
          # F-05 (v0.25.0 peer review): actually MEASURE it.
          #
          # This gate used to emit UNKNOWN unconditionally -- "the cluster API
          # cannot read guest I/O latency". True of the cluster API, but this
          # framework already ships recording rules computing exactly this, and
          # the monitoring stack answering them is on every OCP cluster. The
          # gate was declining to look at data one HTTP request away. Combined
          # with UNKNOWN scoring 0 since R-21, storage latency -- the
          # second-ranked BSOD mechanism in this framework's own KCS catalogue
          # -- contributed nothing to the customer-facing tier under any
          # circumstances.
          #
          # Still degrades to UNKNOWN, never to a pass, whenever the query
          # cannot be made or returns no series: absence of data is not
          # evidence of health. Opt out with BSOD_SKIP_PROM_QUERY=1 (the gate
          # tests set it so fixtures stay offline), same precedent as Gate 8's
          # BSOD_SKIP_MICROCODE_PROBE.
          _lat=""
          if pq_available; then
            _lat=$(pq_vm_worst_latency "$current_ns" "$v" 2>/dev/null) || _lat=""
          fi
          if [ -n "$_lat" ]; then
            _lat_ms=$(awk -v s="$_lat" 'BEGIN{printf "%.1f", s*1000}')
            if awk -v s="$_lat" -v c="$LAT_CRIT_SECONDS" 'BEGIN{exit !(s>=c)}'; then
              flag "storage latency ${_lat_ms}ms/op (worst direction, 1h mean) is at or above the ${LAT_CRIT_SECONDS}s severe-degradation threshold -- individual I/Os in this regime routinely exceed the 60s VirtIO IoTimeoutValue, triggering MEMORY_MANAGEMENT (0x1A) or KERNEL_DATA_INPAGE_ERROR (0x7A) (KCS-7132512)"
            elif awk -v s="$_lat" -v w="$LAT_WARN_SECONDS" 'BEGIN{exit !(s>=w)}'; then
              warn "storage latency ${_lat_ms}ms/op (worst direction, 1h mean) is at or above the ${LAT_WARN_SECONDS}s sustained-degradation threshold -- a LEADING indicator of the tail spikes that breach the 60s VirtIO IoTimeoutValue. Investigate backing storage; consider raising IoTimeoutValue (KCS-7132512)"
            else
              ok "storage latency ${_lat_ms}ms/op (worst direction, 1h mean) is below the ${LAT_WARN_SECONDS}s threshold"
            fi
          else
            unknown "storage latency NOT measured (${PQ_UNAVAILABLE_REASON:-no matching Prometheus series for this VM}) -- absence of data is not evidence of health. Verify via Prometheus BSODRisk_StorageLatency* / guest baselines / analyze.py. If spikes approach the ~60s VirtIO IoTimeoutValue, increase IoTimeoutValue (KCS-7132512)."
          fi
        else
          ok "no PVC-backed disks detected"
        fi
      else
        # H3 follow-up (v0.16.0 #1): "no VMI" is ambiguous -- it could mean
        # the VM is genuinely stopped (silently defer, as before), or it
        # could mean the VMI list itself was unreadable, in which case we
        # cannot even confirm whether the VM is running. Make the latter
        # visible instead of folding it into the same silent deferral.
        if ! _require_evidence "${CACHED_VMI_LIST_JSON_ERR:-0}" "VMI status for $v in namespace $current_ns"; then
          :
        else
          GATE_DEFERRED_COUNT[11]=$(( ${GATE_DEFERRED_COUNT[11]:-0} + 1 ))
        fi
      fi
    fi

    # ---- GATE 13: QEMU Guest Agent health (graceful shutdown, VSS, ballooning) ----
    if gate_enabled 13; then
      set_gate 13
      info "-- Gate 13: QEMU Guest Agent (QGA) communication --"
      if [ -n "$vmi_exists" ]; then
        guest_os_info="$_vmi_guest_os"
        if [ -n "$guest_os_info" ]; then
          ok "QGA reporting guest OS: $guest_os_info (graceful shutdown/VSS/ballooning functional)"
        else
          warn "QGA not reporting guestOSInfo -- graceful shutdown will fail on node drain; VSS snapshots and memory ballooning unavailable"
        fi
      else
        # H3 follow-up (v0.16.0 #1): see Gate 11's identical comment above.
        if ! _require_evidence "${CACHED_VMI_LIST_JSON_ERR:-0}" "VMI status for $v in namespace $current_ns"; then
          :
        else
          GATE_DEFERRED_COUNT[13]=$(( ${GATE_DEFERRED_COUNT[13]:-0} + 1 ))
        fi
      fi
    fi

    # ---- GATE 14: CPU topology / socket count (Windows Desktop licensing) ----
    if gate_enabled 14; then
      set_gate 14
      info "-- Gate 14: CPU topology (Windows socket licensing limit) --"
      sockets="${_F[9]}"
      cores="${_F[10]}"
      threads="${_F[11]}"
      vcpu_cores="${_F[12]}"
      info "  topology: sockets=$sockets, cores=$cores, threads=$threads (total vCPUs=$vcpu_cores)"
      # L-15: the 2-socket cap is a Windows *Desktop* (10/11) licensing limit.
      # Server SKUs are licensed per-core and support up to 64 sockets, so
      # warning on a 4-socket Server 2022 VM was pure noise -- and this gate is
      # customer-facing. Fall back to warning when the edition is unknown
      # (over-report rather than miss a real Desktop violation).
      # Match on lowercased hint. Server tokens are checked FIRST because
      # "windows2k22" contains neither "win2k" nor "win10/11" -- the substring
      # between "win" and the version digits ("dows") breaks naive globs.
      _os_lc=$(printf '%s' "$os" | tr '[:upper:]' '[:lower:]')
      case "$_os_lc" in
        *2k[0-9]*|*server*|*2008*|*2012*|*2016*|*2019*|*2022*|*2025*)
          _is_desktop_edition=0 ;;
        *win10*|*win11*|*win7*|*win8*|*winxp*|*windows10*|*windows11*|*windows7*|*windows8*|*windowsxp*)
          # Master remediation plan (Phase 3): Windows 7/8/8.1/XP are also
          # Desktop-licensed editions subject to the same 2-socket cap as
          # 10/11 -- this branch previously only recognized win10/win11,
          # so a legacy-client VM with >2 sockets fell through to the
          # "unknown edition" WARN below instead of the correct one.
          _is_desktop_edition=1 ;;
        *) _is_desktop_edition=2 ;;   # unknown edition
      esac
      if [ "${sockets:-1}" -gt 2 ] && [ "$_is_desktop_edition" -eq 1 ]; then
        warn "sockets=$sockets exceeds the Windows Desktop limit (max 2). Windows 10/11 will only use 2 sockets -- use cores instead of sockets for full vCPU utilization."
      elif [ "${sockets:-1}" -gt 2 ] && [ "$_is_desktop_edition" -eq 2 ]; then
        warn "sockets=$sockets and the Windows edition could not be determined from '$os'. If this is a Desktop edition (10/11) only 2 sockets will be used; Server editions are unaffected."
      elif [ "${sockets:-1}" -gt 2 ]; then
        ok "socket count ($sockets) -- Server edition, licensed per-core (no 2-socket cap)"
      elif [ "$_TOPOLOGY_UNCONFIRMED" -eq 1 ]; then
        # H3 follow-up (v0.16.0 #1): sockets<=2 here came from a sparse spec
        # default, not a confirmed source -- see the _TOPOLOGY_UNCONFIRMED
        # comment above. Do not report a resolved socket count as passing.
        _require_evidence "${CACHED_VMI_LIST_JSON_ERR:-0}" "VMI status for $v (needed to confirm CPU topology for the socket-licensing check)"
      else
        ok "socket count ($sockets) within Windows licensing limits"
      fi
    fi

    # ---- GATE 15: guest virtio-win version (stream-aware; KCS-7141291) ----
    if gate_enabled 15; then
      set_gate 15 "7141291"
      info "-- Gate 15: guest virtio-win version (stream-aware) --"
      guest_root="${BSOD_GUEST_EVIDENCE_DIR:-./bsod-qga-collect}"
      guest_dir=""
      for candidate in \
          "$guest_root/pre-flight/vms/$current_ns/$v/guest" \
          "$guest_root/vms/$current_ns/$v/guest" \
          "$guest_root/$current_ns/$v/guest"; do
        if [ -d "$candidate" ]; then
          guest_dir="$candidate"
          break
        fi
      done
      guest_ver=""
      if [ -n "$guest_dir" ]; then
        if [ -f "$guest_dir/virtio_version.txt" ]; then
          # collect-windows-guest-info.ps1 writes this file via PowerShell
          # 5.1's `Out-File -Encoding utf8`, which ALWAYS prepends a 3-byte
          # UTF-8 BOM (0xEF 0xBB 0xBF) -- PS 5.1 has no `-Encoding
          # utf8NoBOM` (CLAUDE.md's "PowerShell scripts must target PS 5.1"
          # pitfall). Confirmed live 2026-08-13: a real registry-sourced
          # "1.9.57" collected from a live Windows guest came through as
          # "\xef\xbb\xbf""1.9.57" and graded [WARN] unparseable_version
          # instead of its real stream verdict -- the single highest-value
          # evidence this framework collects (per the "Guest-side evidence"
          # peer-review issue) had never once been successfully parsed on
          # any real PS-5.1 collection before this fix, on either AMD review
          # cluster or this repo's own first live QGA run. `tr -d
          # '[:space:]'` does not strip a BOM (not whitespace), so strip it
          # explicitly first. `insights-rules/plugins/common.py::parse_version`
          # has the matching fix on the Python side.
          guest_ver=$(sed '1s/^\xef\xbb\xbf//' "$guest_dir/virtio_version.txt" | tr -d '[:space:]' | head -c 32)
        fi
        if [ -z "$guest_ver" ] && [ -f "$guest_dir/drv_list.csv" ]; then
          guest_ver=$(awk -F',' '
            NR==1 {
              for (i=1;i<=NF;i++) {
                h=tolower($i); gsub(/"/,"",h)
                if (h ~ /devicename|device name/) dn=i
                if (h ~ /driverversion|driver version|version/) dv=i
              }
              next
            }
            {
              name=tolower($dn); gsub(/"/,"",name)
              ver=$dv; gsub(/"/,"",ver); gsub(/[^0-9.]/,"",ver)
              if (name ~ /virtio|red hat/ && ver ~ /^[0-9]+\.[0-9]+/) {
                print ver; exit
              }
            }' "$guest_dir/drv_list.csv" 2>/dev/null || true)
        fi
      fi
      if [ -n "$guest_ver" ]; then
        evaluate_driver_version_stream "$guest_ver"
        case "$DRIVER_VERDICT" in
          FAIL)
            if [ "${DRIVER_VERDICT_REASON:-}" = "below_tooling_floor" ]; then
              # F-06: cite the COLLECTION utility article, not the BSOD-trigger
              # one. See the WARN arm below for the full rationale -- the same
              # divergence existed on both severities.
              set_gate 15 "7128506"
              flag "guest virtio-win $guest_ver is below the ${TOOLING_FLOOR:-1.9.41} floor this framework's own collection tooling requires -- driver-inventory and remediation steps may fail or return incomplete data. Update virtio-win before relying on guest-side evidence (KCS-7128506)"
              set_gate 15 "7141291"
            else
              flag "guest virtio-win $guest_ver -- stream $STREAM FAIL (threshold < ${STREAM_FAIL:-n/a}) (KCS-7141291)"
            fi
            ;;
          WARN)
            if [ "${DRIVER_VERDICT_REASON:-}" = "binary_format_version" ]; then
              warn "guest virtio-win '$guest_ver' looks like a Windows binary DriverVersion (Win32_PnPSignedDriver build number), not the virtio-win package version -- cannot evaluate stream threshold. Re-run with a registry-sourced package version (bsod-textfile-collector.ps1 / collect-windows-guest-info.ps1)."
            elif [ "${DRIVER_VERDICT_REASON:-}" = "at_stream_max" ]; then
              # F-03: scored as gate 22 (`platform`, weight 0), not gate 15
              # (`driver`, 1.5). On a capped stream this is the ONLY reachable
              # verdict at any driver version -- the ceiling sits below the fix
              # baselines -- so as a driver finding it put an identical 4.50 on
              # every VM in the fleet for something only an OCP upgrade can
              # clear. Still a visible WARN; it just stops inflating the tier.
              #
              # set_gate is restored to 15 immediately below and that restore is
              # LOAD-BEARING: the OS-compatibility WARN that follows this block
              # would otherwise inherit gate 22 and silently score 0 too.
              set_gate 22 "7141291" ""
              warn "guest virtio-win $guest_ver is at the ceiling available for stream $STREAM (max ${STREAM_MAX:-n/a}) -- the BSOD fixes above it are not shippable on this OCP release, so this is a platform coverage limit rather than a VM-level defect. Remediation is an OCP upgrade, not a driver update (KCS-7141291)"
              set_gate 15 "7141291"
            elif [ "${DRIVER_VERDICT_REASON:-}" = "below_tooling_floor" ]; then
              # F-06 (v0.25.0 peer review follow-up). Emitted under KCS-7128506
              # rather than Gate 15's default KCS-7141291, because 7128506
              # ("Windows guest data collection") is a UTILITY article that
              # shared/risk-scoring.json deliberately excludes from
              # kcs_trigger_articles -- "how to collect data" is not "this
              # causes a BSOD". This finding says the driver is too old for the
              # COLLECTION TOOLING, which is a tooling-capability statement.
              #
              # That distinction is worth real score. Python has always cited
              # 7128506 here and scored 3.15 (WARN 3 x driver 1.5 x
              # GENERAL-KNOWLEDGE 0.7); bash cited 7141291 and scored 4.50
              # (KCS-VALIDATED). Same finding, two numbers -- and the
              # (severity, gate, kcs)-keyed contract vectors could never catch
              # it, because they never see which kcs the audit script passes.
              # Reachable in production on el8_6 (OCP 4.12) and el9_2
              # (OCP 4.13-4.15) for any version below the stream ceiling.
              #
              # As elsewhere, the restore to 7141291 is load-bearing for the
              # OS-compatibility WARN emitted after this block.
              set_gate 15 "7128506"
              warn "guest virtio-win $guest_ver is below the ${TOOLING_FLOOR:-1.9.41} floor this framework's own collection tooling requires, and stream $STREAM caps at ${STREAM_MAX:-n/a} so no newer driver is available -- guest-side evidence may be incomplete until OCP is upgraded (KCS-7128506)"
              set_gate 15 "7141291"
            elif [ "${DRIVER_VERDICT_REASON:-}" = "unparseable_version" ]; then
              warn "guest virtio-win version '$guest_ver' is not a parseable package version -- cannot evaluate stream threshold. This is NOT a pass. Re-collect with a registry-sourced package version (bsod-textfile-collector.ps1 / collect-windows-guest-info.ps1); KCS-7141291."
            else
              warn "guest virtio-win $guest_ver -- stream $STREAM WARN (confirm against thresholds; KCS-7141291)"
            fi
            ;;
          PASS)
            ok "guest virtio-win $guest_ver -- stream $STREAM PASS"
            ;;
          *)
            # R-01: never let an unrecognized verdict string fall through to
            # ok(). The previous `*)` catch-all mapped EVERYTHING that was not
            # FAIL/WARN to a green PASS line, so any future verdict value (or a
            # library that failed before setting DRIVER_VERDICT) would print
            # `[ OK ] guest virtio-win <value> -- stream <s> PASS` on the
            # framework's most important guest check. Fail safe instead.
            unknown "guest virtio-win verdict for $v could not be interpreted (verdict='${DRIVER_VERDICT:-unset}', version='$guest_ver') -- treat as unassessed, not as a pass (KCS-7141291)"
            ;;
        esac
      else
        unknown "guest virtio-win version not available for $v -- run cnv-qga-fleet-collect.sh or collect-windows-guest-info.ps1 (cluster API cannot read in-guest drivers; KCS-7141291)"
      fi
      # N-06 (Wave 7, R-47): guest-OS-support axis -- distinct from the
      # stream-version verdict above and evaluated unconditionally (even
      # when guest_ver is empty), because for the legacy OSes this can flag
      # no virtio-win '1.9.x' package this framework tracks ever claimed to
      # support the OS at all, independent of what driver version (if any)
      # is actually installed.
      evaluate_guest_os_driver_compatibility "$os" "$guest_ver"
      if [ "${OS_COMPAT_VERDICT:-}" = "INCOMPATIBLE" ]; then
        warn "guest OS '$os' (${OS_COMPAT_OS_NAME:-legacy Windows}) is not a Red Hat Certified OpenShift Virtualization guest OS (KCS 4234591 -- https://access.redhat.com/articles/4234591) and has no supported virtio-win driver in the '1.9.x' family this framework tracks${OS_COMPAT_CEILING:+ (last known-supported package: $OS_COMPAT_CEILING)} -- a driver-version bump alone cannot fix BSODs here; this is a platform-migration conversation, not a driver-update one (KCS-7141291, shared/virtio-win-guest-os-support.json)"
      fi
    fi

    # ---- GATE 16: Phantom NIC / VMware residue (0xD1 / 0x20001) -- KCS-263043 / 7132519 ----
    if gate_enabled 16; then
      set_gate 16 "263043" "0xD1"
      info "-- Gate 16: phantom NIC / VMware driver residue (0xD1 / 0x20001) --"
      # Re-use guest_root from Gate 15 (same evidence directory)
      guest_root="${BSOD_GUEST_EVIDENCE_DIR:-./bsod-qga-collect}"
      phantom_dir=""
      for candidate in \
          "$guest_root/pre-flight/vms/$current_ns/$v/guest" \
          "$guest_root/vms/$current_ns/$v/guest" \
          "$guest_root/$current_ns/$v/guest"; do
        if [ -d "$candidate" ]; then
          phantom_dir="$candidate"
          break
        fi
      done
      # collect-windows-guest-info.ps1 / cnv-qga-fleet-collect.sh write
      # PhantomNICConfig.csv, PhantomDevices.csv, and vmware_drv_list.csv
      # (real Get-PnpDevice / Win32_PnPSignedDriver CSV column names).
      # FAIL-parity with Python check_vmware_leftover_drivers /
      # is_high_risk_vmware_device (KCS-7132519): active VMware drivers and
      # high-risk phantoms (VMMemCtl/vmxnet/pvscsi/SVGA) are FAIL, other
      # VMware phantoms WARN, phantom-NIC configs stay WARN (KCS-263043).
      # Read vmware_drv_list.csv -- NOT drv_list.csv, which is virtio-filtered
      # and can never contain a VMware driver name (N8).
      nic_count=0
      if [ -n "$phantom_dir" ] && [ -f "$phantom_dir/PhantomNICConfig.csv" ]; then
        nic_count=$(($(wc -l < "$phantom_dir/PhantomNICConfig.csv") - 1))
        [ "$nic_count" -lt 0 ] && nic_count=0
      fi
      vmware_highrisk=0
      vmware_other=0
      if [ -n "$phantom_dir" ] && [ -f "$phantom_dir/PhantomDevices.csv" ]; then
        # Strip a PS 5.1 UTF-8 BOM so the header row still parses. Two
        # integers: high-risk count, then other-VMware count. High-risk names
        # match Python is_high_risk_vmware_device (friendly_name only).
        read -r vmware_highrisk vmware_other < <(sed '1s/^\xef\xbb\xbf//' "$phantom_dir/PhantomDevices.csv" | awk -F',' '
          NR==1 {
            for (i=1;i<=NF;i++) {
              h=tolower($i); gsub(/"/,"",h)
              if (h ~ /friendlyname|friendly name/) fn=i
              if (h ~ /instanceid|instance id/) idn=i
            }
            next
          }
          {
            name=tolower($fn); gsub(/"/,"",name)
            iid=""
            if (idn) { iid=tolower($idn); gsub(/"/,"",iid) }
            is_vmware = (name ~ /vmware|vmxnet|svga|vmmemctl|pvscsi|vm3dmp/ || iid ~ /vmware|vmxnet|svga|vmmemctl|pvscsi|vm3dmp/)
            if (!is_vmware) next
            if (name ~ /vmmemctl|vmxnet|pvscsi|svga/) hr++
            else other++
          }
          END { print hr+0, other+0 }' 2>/dev/null) || true
        vmware_highrisk="${vmware_highrisk:-0}"
        vmware_other="${vmware_other:-0}"
      fi
      vmware_drv_count=0
      if [ -n "$phantom_dir" ] && [ -f "$phantom_dir/vmware_drv_list.csv" ]; then
        # Header-only file is a clean PASS for the driver half (collector
        # always writes the header even when no VMware drivers were found).
        vmware_drv_count=$(sed '1s/^\xef\xbb\xbf//' "$phantom_dir/vmware_drv_list.csv" | awk -F',' '
          NR==1 {
            for (i=1;i<=NF;i++) {
              h=tolower($i); gsub(/"/,"",h)
              if (h ~ /^devicename$/ || h ~ /^driver$/) fn=i
            }
            next
          }
          {
            name=tolower($fn); gsub(/"/,"",name)
            if (name ~ /vmmemctl|vmtools|vmware|vm3dmp|vmxnet|pvscsi/) c++
          }
          END { print c+0 }' 2>/dev/null || echo 0)
      fi
      if [ -z "$phantom_dir" ]; then
        unknown "phantom NIC status unknown for $v -- run cnv-qga-fleet-collect.sh or collect-windows-guest-info.ps1 to check for stale NIC configurations (KCS-263043)"
      else
        # collect-windows-guest-info.ps1 only writes PhantomNICConfig.csv /
        # PhantomDevices.csv when Get-PnpDevice actually found a matching
        # device (write-only-if-nonempty). Since $phantom_dir itself was
        # found, an absent file means "checked, found none" (OK), not
        # "not assessed" (UNKN). UNKN is reserved for a missing guest
        # directory. Do not convert UNKNOWN to OK (R0.3).
        if [ "${nic_count:-0}" -gt 0 ]; then
          warn "$nic_count phantom NIC configuration(s) with stale TCP/IP settings -- may conflict with VirtIO NetKVM (KCS-263043)"
        else
          ok "no phantom NIC configurations detected"
        fi
        # VMware driver + phantom half: FAIL-parity with
        # check_vmware_leftover_drivers. Switch KCS/stop-code for these
        # findings only; phantom-NIC WARNs above stay on 263043/0xD1.
        if [ "${vmware_drv_count:-0}" -gt 0 ]; then
          set_gate 16 "7132519" "0x20001"
          flag "$vmware_drv_count active VMware driver(s) detected -- remove to prevent 0x20001/HYPERVISOR_ERROR (KCS-7132519)"
        fi
        if [ "${vmware_highrisk:-0}" -gt 0 ]; then
          set_gate 16 "7132519" "0x20001"
          flag "$vmware_highrisk high-risk VMware phantom device(s) -- remove immediately to prevent 0x20001/HYPERVISOR_ERROR (KCS-7132519)"
        elif [ "${vmware_other:-0}" -gt 0 ]; then
          set_gate 16 "7132519" "0x20001"
          warn "$vmware_other VMware phantom device(s) detected -- may cause 0xD1/HYPERVISOR_ERROR after migration (KCS-263043, KCS-7132519)"
        elif [ "${vmware_drv_count:-0}" -eq 0 ]; then
          ok "no VMware drivers or phantom devices detected"
        fi
      fi
    fi

    # ---- GATE 21: virtio-win driver source attached (0x7B risk) -- KCS-7141291 ----
    # Master remediation plan Phase 4: no existing gate checked whether a
    # virtio-win containerDisk/CD-ROM was EVER attached at all, distinct from
    # Gate 15 (grades the version of an ALREADY guest-confirmed driver) and
    # Gate 1 (grades the boot disk's bus choice itself). A virtio/scsi-bus
    # boot disk with no source ever attached and no guest evidence of an
    # installed driver likely can't even complete Windows Setup -- Windows
    # has no inbox virtio-blk/vioscsi driver.
    if gate_enabled 21; then
      set_gate 21 "7141291" "0x7B"
      info "-- Gate 21: virtio-win driver source attached (0x7B risk) --"
      _g21_boot_bus="unset"
      if [ -n "${_F[15]}" ]; then
        IFS='|' read -ra _g21_bd_arr <<< "${_F[15]}"
        _g21_boot_bus="${_g21_bd_arr[0]#*=}"
      fi
      case "$_g21_boot_bus" in
        virtio|scsi)
          if [ "${_F[18]}" = "true" ]; then
            ok "virtio-win driver source (containerDisk/CD-ROM) is attached"
          elif gate_enabled 15 && [ -n "${guest_ver:-}" ]; then
            # gate_enabled 15 guard: guest_ver is only reset ("") inside
            # Gate 15's own block, so without this guard a --stop-code
            # filter that disables Gate 15 but not Gate 21 could read a
            # STALE guest_ver left over from a previous VM in the same run.
            ok "no virtio-win source currently attached, but guest evidence confirms virtio-win $guest_ver is already installed"
          else
            warn "boot disk bus '$_g21_boot_bus' requires a virtio-family driver, but no virtio-win containerDisk/CD-ROM is attached and no guest evidence of an installed driver was collected -- Windows Setup has no inbox virtio-blk/vioscsi driver and may fail to boot at all (INACCESSIBLE_BOOT_DEVICE, 0x7B). Attach the virtio-win containerDisk (KCS-7141291) or collect guest evidence (collect-windows-guest-info.ps1) if the driver was already installed and the source subsequently detached"
          fi
          ;;
        *)
          ok "boot disk bus '$_g21_boot_bus' does not require a virtio-family driver"
          ;;
      esac
    fi

    # ---- GATE 20 (per-VM component): alert-blindness for THIS VM -- Issue I ----
    # Gate 20's cluster-scope block (above, run once per cluster) has always
    # reported this as an aggregate WARN listing up to ten VM names. Gemini's
    # review (Issue I) flagged that a coverage gap this consequential --
    # BSODRisk_MemoryPressure and BSODRisk_EvictionBlocked cannot fire for a
    # VM in this state, ever, with no error anywhere -- deserves a finding on
    # the VM's OWN verdict line, not only membership in a separate list an
    # operator has to cross-reference. Gate 6 already demonstrated the cost of
    # that gap concretely: it now catches five VMs the eviction alert is
    # structurally blind to for exactly this reason.
    #
    # Deliberately weighted into the LOWEST domain (coverage, 1.0x in
    # shared/risk-scoring.json's domain_weights, gate_domains["20"] already
    # maps here) rather than any risk domain: this finding says "not being
    # watched", not "at risk". A CRITICAL-tier VM stays CRITICAL; this alone
    # cannot push a clean VM out of LOW.
    if gate_enabled 20; then
      set_gate 20 "" ""
      if echo "${_F[20]}" | grep -qiE '^(windows|win.*)$'; then
        ok "carries a vm.kubevirt.io/os annotation the alerts can select"
      else
        warn "INVISIBLE to annotation-dependent alerts: no vm.kubevirt.io/os annotation matching 'windows|win.*' on spec.template.metadata, so kubevirt_vmi_info carries no 'os' label for this VM and BSODRisk_MemoryPressure + BSODRisk_EvictionBlocked can never fire for it. This is a coverage gap, not a directly detected risk. Fix: annotate spec.template.metadata.annotations['vm.kubevirt.io/os']"
        if [ "$SUGGEST_ANNOTATE" -eq 1 ]; then
          _gate20_suggest_cmd "$current_ns" "$v" "${_F[21]}" "${_F[22]}"
        fi
      fi
    fi

    # Track evidence gaps per VM (guest-side data not collected).
    # L-16: only meaningful when the gates that gather that evidence actually
    # ran. Under --stop-code, gates 15/16 may be filtered out entirely, in which
    # case guest evidence was never sought and reporting a "gap" for every VM is
    # noise, not signal.
    if gate_enabled 15 || gate_enabled 16; then
      if [ "${guest_ver:-}" = "" ] 2>/dev/null || [ "${phantom_dir:-}" = "" ]; then
        EVIDENCE_GAP_COUNT=$((EVIDENCE_GAP_COUNT+1))
      fi
    fi

    # Track per-VM findings for JSON and namespace counters
    TOTAL_VMS=$((TOTAL_VMS+1))
    NS_VM_COUNT["$current_ns"]=$(( ${NS_VM_COUNT["$current_ns"]:-0} + 1 ))

    local_new_findings=$((FINDINGS - local_findings_before))
    local_new_warnings=$((WARNINGS - local_warnings_before))
    local_new_unknowns=$((UNKNOWNS - local_unknowns_before))
    local_new_passes=$((PASSES - local_passes_before))
    if [ "$local_new_findings" -gt 0 ]; then
      NS_FAIL_COUNT["$current_ns"]=$(( ${NS_FAIL_COUNT["$current_ns"]:-0} + 1 ))
    elif [ "$local_new_warnings" -gt 0 ]; then
      NS_WARN_COUNT["$current_ns"]=$(( ${NS_WARN_COUNT["$current_ns"]:-0} + 1 ))
    elif [ "$local_new_unknowns" -gt 0 ]; then
      # N2: a VM whose only findings are UNKNOWN (evidence missing/uninterpretable)
      # must never be counted as PASS or reported "all checks passed" -- that
      # would be the exact "PASS on absent evidence" the severity contract
      # (v0.15.0 Phase 2) was built to eliminate, recurring one layer downstream.
      NS_UNKNOWN_COUNT["$current_ns"]=$(( ${NS_UNKNOWN_COUNT["$current_ns"]:-0} + 1 ))
    else
      TOTAL_PASS=$((TOTAL_PASS+1))
      NS_PASS_COUNT["$current_ns"]=$(( ${NS_PASS_COUNT["$current_ns"]:-0} + 1 ))
    fi

    # Per-VM verdict line with risk tier
    _vm_tier=$(risk_tier "$local_new_findings" "$local_new_warnings")

    # R-21 (v0.19.0 unified review U-18): EVIDENCE COMPLETENESS as its own axis.
    #
    # UNKNOWN no longer contributes to the tier (see
    # shared/risk-scoring.json's _why_unknown_is_zero), which is what makes the
    # tier discriminate again -- but it also means the tier alone can no longer
    # tell an operator that a VM was barely assessed. The two facts are now two
    # numbers, and the GUARD is that they are always printed together: a tier is
    # never emitted without its evidence percentage beside it.
    #
    # Denominator is the checks this VM actually reached, so it reads as "of
    # what we tried to assess, how much did we manage to".
    _vm_assessed=$(( local_new_findings + local_new_warnings + local_new_passes ))
    _vm_total=$(( _vm_assessed + local_new_unknowns ))
    if [ "$_vm_total" -gt 0 ]; then
      _vm_evidence=$(( _vm_assessed * 100 / _vm_total ))
    else
      _vm_evidence=0
    fi
    _ev="evidence ${_vm_evidence}%"
    [ "$local_new_unknowns" -gt 0 ] && _ev="$_ev, ${local_new_unknowns} unassessed"

    # Issue K: accumulate into the fleet-wide totals declared above.
    FLEET_ASSESSED_TOTAL=$((FLEET_ASSESSED_TOTAL + _vm_assessed))
    FLEET_CHECKS_TOTAL=$((FLEET_CHECKS_TOTAL + _vm_total))

    if ! _no_output; then
      if [ "$local_new_findings" -gt 0 ]; then
        red "── $v [$_vm_tier | $_ev]: $local_new_findings FAIL, $local_new_warnings WARN ──"
      elif [ "$local_new_warnings" -gt 0 ]; then
        amber "── $v [$_vm_tier | $_ev]: $local_new_warnings WARN ──"
      elif [ "$local_new_unknowns" -gt 0 ]; then
        amber "── $v [$_vm_tier | $_ev]: $local_new_unknowns UNASSESSED (evidence missing -- NOT a pass) ──"
      else
        # Even an all-clear states its evidence basis: "no risk found" and
        # "everything was checked" are different claims, and conflating them is
        # the false all-clear this framework exists to prevent.
        green "── $v [$_vm_tier | $_ev]: all checks passed ──"
      fi
    fi

    # Collect executive summary data
    EXEC_VM_NAMES+=("$v")
    EXEC_VM_NS+=("$current_ns")
    EXEC_VM_FAILS+=("$local_new_findings")
    EXEC_VM_WARNS+=("$local_new_warnings")
    EXEC_VM_UNKNOWNS+=("$local_new_unknowns")
    # Capture top issue for summary table
    # L-11: read the plain shadow arrays instead of re-parsing the JSON
    # records with jq. Besides saving two forks per VM, this is the reason
    # text mode can skip building those records at all.
    _first_msg_of_severity() {
      local want="$1" i
      for i in "${!CURRENT_VM_SEV[@]}"; do
        if [ "${CURRENT_VM_SEV[$i]}" = "$want" ]; then
          printf '%s' "${CURRENT_VM_MSG[$i]}"
          return 0
        fi
      done
    }
    top_issue=""
    if [ "$local_new_findings" -gt 0 ]; then
      top_issue=$(_first_msg_of_severity FAIL)
      EXEC_FAIL_VMS+=("$v")
      EXEC_FAIL_DETAILS+=("${top_issue:-unknown}")
    elif [ "$local_new_warnings" -gt 0 ]; then
      top_issue=$(_first_msg_of_severity WARN)
    elif [ "$local_new_unknowns" -gt 0 ]; then
      top_issue=$(_first_msg_of_severity UNKNOWN)
      top_issue="UNASSESSED: ${top_issue:-evidence missing}"
    fi
    EXEC_VM_TOP_ISSUE+=("${top_issue:-all checks passed}")
    EXEC_VM_TIER+=("$_vm_tier")

    # Accumulate VM findings for JSON doc output
    if [ "${#CURRENT_VM_FINDINGS[@]}" -gt 0 ] || [ "$JSON_MODE" = "doc" ]; then
      vm_record=$(jq -n \
        --arg namespace "$current_ns" \
        --arg name "$v" \
        --arg os_hint "$os" \
        --argjson findings "$(printf '%s\n' "${CURRENT_VM_FINDINGS[@]:-}" | jq -s '.')" \
        --argjson evidence_completeness "$_vm_evidence" \
        --argjson assessed_count "$_vm_assessed" \
        --argjson unassessed_count "$local_new_unknowns" \
        --arg tier "$_vm_tier" \
        --argjson fail_count "$local_new_findings" \
        --argjson warn_count "$local_new_warnings" \
        '{namespace: $namespace, name: $name, os_hint: $os_hint, findings: $findings, evidence_completeness: $evidence_completeness, assessed_count: $assessed_count, unassessed_count: $unassessed_count, tier: $tier, fail_count: $fail_count, warn_count: $warn_count}')
      JSON_FINDINGS_VMS+=("$vm_record")
    fi

    # Write per-VM output file if --output-dir is set
    if [ -n "$OUTPUT_DIR" ]; then
      mkdir -p "$OUTPUT_DIR/$current_ns" 2>/dev/null || true
      if [ "${#CURRENT_VM_FINDINGS[@]}" -gt 0 ]; then
        printf '%s\n' "${CURRENT_VM_FINDINGS[@]}" | jq -s \
          --arg namespace "$current_ns" \
          --arg name "$v" \
          --arg os_hint "${os:-}" \
          --argjson fail_count "$local_new_findings" \
          --argjson warn_count "$local_new_warnings" \
          '{namespace: $namespace, name: $name, os_hint: $os_hint, fail_count: $fail_count, warn_count: $warn_count, findings: .}' \
          > "$OUTPUT_DIR/$current_ns/${v}.json" 2>/dev/null || true
      fi
    fi

    _IN_VM_LOOP=0
  done
done

# Clear progress indicator before summary
[ "$JSON_MODE" = "" ] && [ -t 2 ] && printf '\r\033[K' >&2

# Issue K: fleet-wide evidence-completeness aggregate, from the running totals
# accumulated per-VM above. Same shape as each VM's own _vm_evidence: 0 when
# nothing was assessed (no VMs, or every check on every VM was UNKNOWN),
# never a divide-by-zero.
if [ "$FLEET_CHECKS_TOTAL" -gt 0 ]; then
  FLEET_EVIDENCE_PCT=$(( FLEET_ASSESSED_TOTAL * 100 / FLEET_CHECKS_TOTAL ))
else
  FLEET_EVIDENCE_PCT=0
fi

# --- Summary ---
if [ "$JSON_MODE" = "" ]; then
  echo
  echo "=============================================================="

  # Count VMs needing action vs review
  _fail_vm_count="${#EXEC_FAIL_VMS[@]}"
  _warn_only_count=0
  _unknown_only_count=0
  _pass_count=0
  for i in "${!EXEC_VM_NAMES[@]}"; do
    if [ "${EXEC_VM_FAILS[$i]}" -eq 0 ] && [ "${EXEC_VM_WARNS[$i]}" -gt 0 ]; then
      _warn_only_count=$((_warn_only_count+1))
    elif [ "${EXEC_VM_FAILS[$i]}" -eq 0 ] && [ "${EXEC_VM_WARNS[$i]}" -eq 0 ] \
         && [ "${EXEC_VM_UNKNOWNS[$i]:-0}" -gt 0 ]; then
      # N2: never count an UNKNOWN-only VM (evidence missing) as PASS.
      _unknown_only_count=$((_unknown_only_count+1))
    elif [ "${EXEC_VM_FAILS[$i]}" -eq 0 ] && [ "${EXEC_VM_WARNS[$i]}" -eq 0 ]; then
      _pass_count=$((_pass_count+1))
    fi
  done

  _review_count=$((_warn_only_count + _unknown_only_count))
  if [ "$FINDINGS" -eq 0 ] && [ "$WARNINGS" -eq 0 ] && [ "$UNKNOWNS" -eq 0 ]; then
    green " SUMMARY: $TOTAL_VMS Windows VM(s) audited | all checks passed"
  elif [ "$FINDINGS" -eq 0 ]; then
    amber " SUMMARY: $TOTAL_VMS Windows VM(s) audited | $_review_count need review"
  else
    red " SUMMARY: $TOTAL_VMS Windows VM(s) audited | $_fail_vm_count need fixes | $_review_count need review"
  fi
  if [ "$UNKNOWNS" -gt 0 ]; then
    echo " $UNKNOWNS check(s) UNASSESSED -- required evidence was missing."
    echo " These are NOT passes. Collect guest evidence (cnv-qga-fleet-collect.sh)"
    echo " and re-run before treating the affected VMs as low-risk."
  fi
  echo "=============================================================="

  # ACTION REQUIRED: list VMs with FAILs
  if [ "${#EXEC_FAIL_VMS[@]}" -gt 0 ]; then
    echo
    red " ACTION REQUIRED (${#EXEC_FAIL_VMS[@]} VM(s) -- fix before migrating):"
    for i in "${!EXEC_FAIL_VMS[@]}"; do
      _detail="${EXEC_FAIL_DETAILS[$i]}"
      [ "${#_detail}" -gt 72 ] && _detail="${_detail:0:69}..."
      echo "   ${EXEC_FAIL_VMS[$i]}: $_detail"
    done
  fi

  # CLUSTER-WIDE PATTERNS: gates that fire on >50% of VMs
  _cluster_wide_shown=0
  if [ "$TOTAL_VMS" -gt 0 ]; then
    _threshold=$(( (TOTAL_VMS + 1) / 2 ))
    [ "$_threshold" -lt 3 ] && _threshold=3
    for gate_id in $(echo "${!GATE_WARN_COUNT[@]}" | tr ' ' '\n' | sort -n); do
      count="${GATE_WARN_COUNT[$gate_id]}"
      if [ "$count" -ge "$_threshold" ]; then
        if [ "$_cluster_wide_shown" -eq 0 ]; then
          echo
          echo " CLUSTER-WIDE OBSERVATIONS (apply to most/all VMs):"
          _cluster_wide_shown=1
        fi
        _msg="${GATE_WARN_MSG[$gate_id]}"
        [ "${#_msg}" -gt 72 ] && _msg="${_msg:0:69}..."
        echo "   $count/$TOTAL_VMS VMs: $_msg"
      fi
    done
    if [ "$_cluster_wide_shown" -eq 1 ] && [ "$SUMMARY_ONLY" -eq 0 ]; then
      echo "   (These appear on most VMs below. Use --summary-only to see just verdicts.)"
    fi
  fi

  # DEFERRED CHECKS (VMI not running)
  _deferred_shown=0
  for _dg in $(echo "${!GATE_DEFERRED_COUNT[@]}" | tr ' ' '\n' | sort -n); do
    _dc="${GATE_DEFERRED_COUNT[$_dg]}"
    if [ "$_dc" -gt 0 ]; then
      if [ "$_deferred_shown" -eq 0 ]; then
        echo
        echo " DEFERRED CHECKS (VM not running -- start VMs and rerun for full coverage):"
        _deferred_shown=1
      fi
      case "$_dg" in
        6)  echo "   Gate 6 (live-migratability): $_dc/$TOTAL_VMS VM(s) skipped -- evictionStrategy verified, but LiveMigratable needs a running VMI" ;;
        11) echo "   Gate 11 (storage latency): $_dc/$TOTAL_VMS VM(s) skipped" ;;
        13) echo "   Gate 13 (QGA communication): $_dc/$TOTAL_VMS VM(s) skipped" ;;
        *)  echo "   Gate $_dg: $_dc/$TOTAL_VMS VM(s) skipped" ;;
      esac
    fi
  done

  # EVIDENCE GAPS
  if [ "$EVIDENCE_GAP_COUNT" -gt 0 ] && [ "$TOTAL_VMS" -gt 0 ]; then
    echo
    amber " EVIDENCE GAPS: $EVIDENCE_GAP_COUNT of $TOTAL_VMS VM(s) missing guest-side data"
    echo "   Guest driver versions and device inventory require in-guest collection."
    echo "   Some warnings above may resolve once guest data is collected."
  fi

  # NEXT STEPS
  echo
  echo " NEXT STEPS:"
  if [ "${#EXEC_FAIL_VMS[@]}" -gt 0 ]; then
    echo "   1. Fix the ${#EXEC_FAIL_VMS[@]} ACTION REQUIRED VM(s) above"
    echo "   2. Run: ./cnv-qga-fleet-collect.sh -n <namespace> --all-windows -o /tmp/bsod-data"
    echo "      This collects driver versions and configurations from inside each Windows VM"
    echo "   3. Attach this output + collector output to your Red Hat support case"
  else
    echo "   1. Run: ./cnv-qga-fleet-collect.sh -n <namespace> --all-windows -o /tmp/bsod-data"
    echo "      This collects driver versions and configurations from inside each Windows VM"
    echo "   2. Review warnings and attach this output to your Red Hat support case"
  fi
  if [ "$STRICT" -eq 1 ]; then
    echo " Mode: --strict (migration-critical warnings promoted to failures)"
  fi
  echo " Reminder: confirm virtio-win >= $DRIVER_BASELINE INSIDE each Windows"
  echo " guest (collection tooling needs >= $TOOLING_FLOOR). Cluster spec"
  echo " cannot read the in-guest driver version."
  echo " NOTE: This gate covers cluster-visible checks only. Run the full"
  echo " Python analyzer (insights-rules/analyze.py) for comprehensive coverage"
  echo " including guest-side evidence, crash dump analysis, and vendor routing."

  # Multi-namespace breakdown
  if [ "${#NAMESPACES[@]}" -gt 1 ]; then
    echo
    printf ' %-30s %-5s %-5s %-5s %-8s %-5s\n' "NAMESPACE" "VMS" "FAIL" "WARN" "UNKNOWN" "PASS"
    printf ' %-30s %-5s %-5s %-5s %-8s %-5s\n' "------------------------------" "-----" "-----" "-----" "--------" "-----"
    for ns_key in "${NAMESPACES[@]}"; do
      [ "${NS_VM_COUNT[$ns_key]:-0}" -eq 0 ] && continue
      printf ' %-30s %-5s %-5s %-5s %-8s %-5s\n' \
        "$ns_key" "${NS_VM_COUNT[$ns_key]:-0}" "${NS_FAIL_COUNT[$ns_key]:-0}" \
        "${NS_WARN_COUNT[$ns_key]:-0}" "${NS_UNKNOWN_COUNT[$ns_key]:-0}" "${NS_PASS_COUNT[$ns_key]:-0}"
    done
  fi

  # Summary-only mode: per-VM verdict table
  if [ "$SUMMARY_ONLY" -eq 1 ] && [ "${#EXEC_VM_NAMES[@]}" -gt 0 ]; then
    echo
    printf ' %-30s %-10s %-5s %-5s %-8s  %s\n' "VM" "RISK" "FAIL" "WARN" "UNKNOWN" "TOP ISSUE"
    printf ' %-30s %-10s %-5s %-5s %-8s  %s\n' "------------------------------" "----------" "-----" "-----" "--------" "------------------------------"
    for i in "${!EXEC_VM_NAMES[@]}"; do
      _vm="${EXEC_VM_NAMES[$i]}"
      [ "${#_vm}" -gt 30 ] && _vm="${_vm:0:27}..."
      _tier="${EXEC_VM_TIER[$i]}"
      _top="${EXEC_VM_TOP_ISSUE[$i]}"
      [ "${#_top}" -gt 42 ] && _top="${_top:0:39}..."
      printf ' %-30s %-10s %-5s %-5s %-8s  %s\n' "$_vm" "$_tier" "${EXEC_VM_FAILS[$i]}" \
        "${EXEC_VM_WARNS[$i]}" "${EXEC_VM_UNKNOWNS[$i]:-0}" "$_top"
    done
  fi

  echo "=============================================================="
elif [ "$JSON_MODE" = "doc" ]; then
  # Emit single JSON document
  _cluster_json="[]"
  if [ "${#JSON_FINDINGS_CLUSTER[@]}" -gt 0 ]; then
    _cluster_json=$(printf '%s\n' "${JSON_FINDINGS_CLUSTER[@]}" | jq -s '.')
  fi
  _vms_json="[]"
  if [ "${#JSON_FINDINGS_VMS[@]}" -gt 0 ]; then
    _vms_json=$(printf '%s\n' "${JSON_FINDINGS_VMS[@]}" | jq -s '.')
  fi
  _ns_json=$(printf '%s\n' "${NAMESPACES[@]}" | jq -R -s 'split("\n") | map(select(. != ""))')

  # ARG_MAX guard (found live against cluster-thdjk, 2026-08-05, deploying
  # Issue K's exporter for the first time as a real in-cluster Pod): passing
  # a fleet-sized _vms_json/_cluster_json to jq via --argjson puts the ENTIRE
  # blob on the process's argv, which shares the kernel's single ARG_MAX
  # budget with envp -- and Kubernetes auto-injects a `<SVC>_SERVICE_HOST`/
  # `_PORT` pair for every Service the pod's namespace can see (openshift-cnv
  # carries dozens from the CNV operator alone). At a 68-VM real fleet this
  # combination hit "/usr/bin/jq: Argument list too long", jq exited
  # non-zero, command substitution produced an empty string, and
  # collect_once() correctly treated that as a hard collection failure --
  # this is silent data loss on a live audit run, not a cosmetic bug.
  # --slurpfile reads the same JSON from a FILE instead of argv, which has
  # no such limit; each temp file holds only this run's own findings and is
  # removed immediately after jq reads it.
  _doc_tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/bsod-audit-doc.XXXXXX")
  printf '%s' "$_ns_json" > "$_doc_tmpdir/namespaces.json"
  printf '%s' "$_cluster_json" > "$_doc_tmpdir/cluster_findings.json"
  printf '%s' "$_vms_json" > "$_doc_tmpdir/vms.json"

  jq -n \
    --arg version "1.0" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg ocp_version "${OCP_VER:-}" \
    --arg stream "${STREAM:-}" \
    --slurpfile _namespaces "$_doc_tmpdir/namespaces.json" \
    --slurpfile _cluster_findings "$_doc_tmpdir/cluster_findings.json" \
    --slurpfile _vms "$_doc_tmpdir/vms.json" \
    --argjson cluster_fail "$FINDINGS" \
    --argjson cluster_warn "$WARNINGS" \
    --argjson cluster_unknown "$UNKNOWNS" \
    --argjson total_vms "$TOTAL_VMS" \
    --argjson total_pass "$TOTAL_PASS" \
    --argjson evidence_completeness_pct "$FLEET_EVIDENCE_PCT" \
    '{version: $version, timestamp: $timestamp, ocp_version: $ocp_version, stream: $stream, namespaces: $_namespaces[0], cluster_scope: {findings: $_cluster_findings[0], fail_count: $cluster_fail, warn_count: $cluster_warn, unknown_count: $cluster_unknown}, vms: $_vms[0], summary: {total_vms: $total_vms, fail: ($cluster_fail), warn: ($cluster_warn), unknown: $cluster_unknown, pass: $total_pass, evidence_completeness_pct: $evidence_completeness_pct}}'
  rm -rf "$_doc_tmpdir"
elif [ "$JSON_MODE" = "ndjson" ]; then
  jq -c -n \
    --argjson total_vms "$TOTAL_VMS" \
    --argjson fail "$FINDINGS" \
    --argjson warn "$WARNINGS" \
    --argjson unknown "$UNKNOWNS" \
    --argjson pass "$TOTAL_PASS" \
    --argjson evidence_completeness_pct "$FLEET_EVIDENCE_PCT" \
    '{type: "summary", total_vms: $total_vms, fail: $fail, warn: $warn, unknown: $unknown, pass: $pass, evidence_completeness_pct: $evidence_completeness_pct}'
fi

# Write summary to output-dir if set
if [ -n "$OUTPUT_DIR" ] && [ "$JSON_MODE" = "doc" ]; then
  _cluster_json="[]"
  if [ "${#JSON_FINDINGS_CLUSTER[@]}" -gt 0 ]; then
    _cluster_json=$(printf '%s\n' "${JSON_FINDINGS_CLUSTER[@]}" | jq -s '.')
  fi
  _vms_json="[]"
  if [ "${#JSON_FINDINGS_VMS[@]}" -gt 0 ]; then
    _vms_json=$(printf '%s\n' "${JSON_FINDINGS_VMS[@]}" | jq -s '.')
  fi
  jq -n \
    --arg version "1.0" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson total_vms "$TOTAL_VMS" \
    --argjson fail "$FINDINGS" \
    --argjson warn "$WARNINGS" \
    --argjson unknown "$UNKNOWNS" \
    --argjson pass "$TOTAL_PASS" \
    --argjson evidence_completeness_pct "$FLEET_EVIDENCE_PCT" \
    '{version: "1.0", timestamp: $timestamp, summary: {total_vms: $total_vms, fail: $fail, warn: $warn, unknown: $unknown, pass: $pass, evidence_completeness_pct: $evidence_completeness_pct}}' \
    > "$OUTPUT_DIR/summary.json"
fi

if [ "$FINDINGS" -gt 0 ]; then
  exit 1
fi

# H2 (v0.16.0): opt-in non-zero exit when any check could not be evaluated.
#
# DEFAULT OFF, deliberately. UNKNOWN is not a failure -- it is "we could not
# look" -- and analyze.py's module docstring documents the same contract for
# the Python layer ("UNKNOWN-severity findings do NOT affect the exit code").
# Changing that globally would break cross-layer parity and every existing
# caller that reads exit 0 as "no confirmed failures".
#
# But an UNATTENDED consumer needs the stricter reading: for the Tekton PreHook
# Job, Kubernetes Job success IS the migration decision, with no human to read
# the UNKNOWN count. A stopped Windows VM with no guest evidence produces
# all-UNKNOWN findings and previously exited 0, letting MTV migrate a VM this
# framework never actually assessed. `--strict` did not help: it promotes WARN
# to FAIL, and nothing promoted UNKNOWN.
#
# So the strictness lives with the consumer that needs it, not in the contract.
if [ "$FAIL_ON_UNKNOWN" -eq 1 ] && [ "$UNKNOWNS" -gt 0 ]; then
  if [ "$JSON_MODE" = "" ]; then
    red "EXIT 1: --fail-on-unknown set and $UNKNOWNS check(s) could not be evaluated."
    red "        This VM was NOT assessed as safe -- it was not fully assessed at all."
  fi
  exit 1
fi
exit 0
