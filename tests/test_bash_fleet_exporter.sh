#!/usr/bin/env bash
# test_bash_fleet_exporter.sh -- Offline unit harness for
# scripts/cnv-bsod-fleet-exporter.sh's write_metrics()/collect_once()
# (Issue K). Sources the script with BSOD_EXPORTER_SOURCE_ONLY=1 so the HTTP
# server and infinite collection loop never start; AUDIT_SCRIPT is pointed at
# small fixture stubs standing in for cnv-win-bsod-audit.sh --json output.
# No cluster, no jq-mocking of `oc` -- this only tests the exporter's own
# JSON-to-Prometheus-text reshaping, not the audit script itself (that is
# test_bash_gates.sh's job).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPORTER_SCRIPT="$SCRIPT_DIR/../scripts/cnv-bsod-fleet-exporter.sh"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

# make_stub <name> <stdout-json> <exit-code>: writes an executable script at
# $WORKDIR/<name> that prints the given JSON on stdout and exits with the
# given code -- a stand-in for cnv-win-bsod-audit.sh --json.
make_stub() {
  local name="$1" json="$2" exit_code="$3"
  local path="$WORKDIR/$name"
  cat > "$path" <<STUB
#!/usr/bin/env bash
cat <<'JSON'
$json
JSON
exit $exit_code
STUB
  chmod +x "$path"
  echo "$path"
}

# run_collect_once <audit_script>: sources the exporter in source-only mode
# in a fresh subshell, points AUDIT_SCRIPT at the given stub, runs
# collect_once once, and prints the resulting metrics file content plus the
# collect_once exit code on the last line as "EXIT=<n>".
run_collect_once() {
  local audit_script="$1"
  local metrics_dir="$WORKDIR/metrics-$$-$RANDOM"
  (
    export AUDIT_SCRIPT="$audit_script"
    export EXPORTER_METRICS_DIR="$metrics_dir"
    export BSOD_EXPORTER_SOURCE_ONLY=1
    # shellcheck disable=SC1090
    source "$EXPORTER_SCRIPT"
    collect_once
    rc=$?
    cat "$metrics_dir/metrics.prom" 2>/dev/null
    echo "EXIT=$rc"
  )
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: $label -- expected to find: $needle"
    echo "---- actual output ----"
    echo "$haystack"
    echo "---- end actual output ----"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: $label -- did NOT expect to find: $needle"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# assert_no_metric_line <label> <haystack> <metric_name>: stricter than
# assert_not_contains -- matches only an actual `<metric_name>{...} <value>`
# or `# TYPE <metric_name> ...` series line, not any substring occurrence.
# Needed because HELP text legitimately documents the PromQL recording rule
# name (bsod:fleet_evidence_completeness:ratio, colon-separated) that
# consumes bsod_vm_checks_assessed/_total -- a plain substring check on
# "fleet_evidence_completeness" would false-positive on that HELP text even
# though no such metric (underscore-separated, no colons) is ever emitted.
assert_no_metric_line() {
  local label="$1" haystack="$2" metric_name="$3"
  if ! grep -Eq "^(${metric_name})(\{|[[:space:]])|^# TYPE ${metric_name} " <<<"$haystack"; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "FAIL: $label -- did NOT expect a $metric_name series/TYPE line"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# --- Scenario 1: healthy multi-VM collection ---
good_json='{"version":"1.0","summary":{"total_vms":2,"fail":0,"warn":1,"unknown":1,"pass":1,"evidence_completeness_pct":75},"vms":[{"namespace":"win-vms","name":"win2k22-good","evidence_completeness":100,"assessed_count":21,"unassessed_count":0},{"namespace":"win-vms","name":"win2k22-partial","evidence_completeness":50,"assessed_count":10,"unassessed_count":10}]}'
stub=$(make_stub "audit-good.sh" "$good_json" 0)
out=$(run_collect_once "$stub")
assert_contains "collect_once/good -- exits 0" "$out" "EXIT=0"
assert_contains "collect_once/good -- per-VM gauge for win2k22-good" "$out" 'bsod_evidence_completeness_percent{namespace="win-vms",vm="win2k22-good"} 100'
assert_contains "collect_once/good -- per-VM gauge for win2k22-partial" "$out" 'bsod_evidence_completeness_percent{namespace="win-vms",vm="win2k22-partial"} 50'
assert_contains "collect_once/good -- HELP line present" "$out" "HELP bsod_evidence_completeness_percent"
assert_contains "collect_once/good -- health gauge success=1" "$out" "bsod_evidence_exporter_last_collection_success 1"
assert_contains "collect_once/good -- checks_assessed gauge for win2k22-good" "$out" 'bsod_vm_checks_assessed{namespace="win-vms",vm="win2k22-good"} 21'
assert_contains "collect_once/good -- checks_total gauge for win2k22-good (21 assessed + 0 unassessed)" "$out" 'bsod_vm_checks_total{namespace="win-vms",vm="win2k22-good"} 21'
assert_contains "collect_once/good -- checks_assessed gauge for win2k22-partial" "$out" 'bsod_vm_checks_assessed{namespace="win-vms",vm="win2k22-partial"} 10'
assert_contains "collect_once/good -- checks_total gauge for win2k22-partial (10 assessed + 10 unassessed)" "$out" 'bsod_vm_checks_total{namespace="win-vms",vm="win2k22-partial"} 20'
assert_contains "collect_once/good -- interval-floor gauge present and 0 (small fleet, default tiers)" "$out" "bsod_evidence_exporter_interval_below_recommended 0"
assert_no_metric_line "collect_once/good -- no fleet-level pre-aggregation gauge (Issue K design: per-VM only, sum()/sum() happens in the recording rule)" "$out" "bsod_fleet_evidence_completeness"

# --- Scenario 2: audit script exits 1 (a FAIL was found) but still produces
# valid JSON -- this is a normal outcome, not a collection failure, and must
# still be treated as a successful collection (health gauge = 1). ---
fail_json='{"version":"1.0","summary":{"total_vms":1,"fail":1,"warn":0,"unknown":0,"pass":9,"evidence_completeness_pct":100},"vms":[{"namespace":"win-vms","name":"win2k22-bad","evidence_completeness":100,"assessed_count":21,"unassessed_count":0}]}'
stub=$(make_stub "audit-fail-exit.sh" "$fail_json" 1)
out=$(run_collect_once "$stub")
assert_contains "collect_once/fail-exit-but-valid-json -- collection still succeeds" "$out" "bsod_evidence_exporter_last_collection_success 1"
assert_contains "collect_once/fail-exit-but-valid-json -- per-VM gauge still emitted" "$out" 'bsod_evidence_completeness_percent{namespace="win-vms",vm="win2k22-bad"} 100'

# --- Scenario 3: audit script produces empty output (e.g. crashed before
# printing anything) -- must be treated as a collection failure, not
# vacuously valid (the bug `jq empty` alone would have missed). ---
stub=$(make_stub "audit-empty.sh" "" 1)
# make_stub always prints something via heredoc; force truly empty stdout.
cat > "$WORKDIR/audit-empty.sh" <<'STUB'
#!/usr/bin/env bash
exit 1
STUB
chmod +x "$WORKDIR/audit-empty.sh"
out=$(run_collect_once "$WORKDIR/audit-empty.sh")
assert_contains "collect_once/empty-output -- collect_once reports failure" "$out" "EXIT=1"
assert_contains "collect_once/empty-output -- health gauge success=0" "$out" "bsod_evidence_exporter_last_collection_success 0"
assert_not_contains "collect_once/empty-output -- no stale per-VM gauge line emitted" "$out" 'bsod_evidence_completeness_percent{namespace='

# --- Scenario 4: audit script produces malformed (non-JSON) output. ---
stub=$(make_stub "audit-malformed.sh" 'not { valid json at all' 0)
out=$(run_collect_once "$stub")
assert_contains "collect_once/malformed-json -- collect_once reports failure" "$out" "EXIT=1"
assert_contains "collect_once/malformed-json -- health gauge success=0" "$out" "bsod_evidence_exporter_last_collection_success 0"

# --- Scenario 5: JSON is valid but has no .summary object (e.g. a stray '{}'
# -- the exact case the plain `jq empty` check would have missed). ---
stub=$(make_stub "audit-no-summary.sh" '{}' 0)
out=$(run_collect_once "$stub")
assert_contains "collect_once/no-summary -- collect_once reports failure" "$out" "EXIT=1"
assert_contains "collect_once/no-summary -- health gauge success=0" "$out" "bsod_evidence_exporter_last_collection_success 0"

# --- Scenario 6: zero VMs in scope -- must not error, must emit no per-VM
# gauge lines, and must still report a successful collection. ---
empty_fleet_json='{"version":"1.0","summary":{"total_vms":0,"fail":0,"warn":0,"unknown":0,"pass":0,"evidence_completeness_pct":0},"vms":[]}'
stub=$(make_stub "audit-empty-fleet.sh" "$empty_fleet_json" 0)
out=$(run_collect_once "$stub")
assert_contains "collect_once/empty-fleet -- exits 0" "$out" "EXIT=0"
assert_contains "collect_once/empty-fleet -- health gauge success=1" "$out" "bsod_evidence_exporter_last_collection_success 1"
assert_not_contains "collect_once/empty-fleet -- no per-VM gauge lines" "$out" 'bsod_evidence_completeness_percent{namespace='

# --- Scenario 7: interval floor -- tier 1 (>= 500 VMs by default) breached.
# EXPORTER_INTERVAL_SECONDS defaults to 300s, which is exactly at, not below,
# the default tier-1 floor -- use a deliberately short override so the
# comparison is unambiguous rather than depending on the default matching
# exactly. ---
tier1_json='{"version":"1.0","summary":{"total_vms":600,"fail":0,"warn":0,"unknown":0,"pass":600,"evidence_completeness_pct":100},"vms":[]}'
stub=$(make_stub "audit-tier1.sh" "$tier1_json" 0)
out=$(
  EXPORTER_INTERVAL_SECONDS=120 run_collect_once "$stub"
)
assert_contains "collect_once/interval-floor-tier1 -- gauge set to 1 when 600 VMs with 120s interval (< 300s tier-1 floor)" "$out" "bsod_evidence_exporter_interval_below_recommended 1"

# --- Scenario 8: interval floor -- tier 2 (>= 2000 VMs by default) breached,
# even though the interval clears the tier-1 floor on its own. ---
tier2_json='{"version":"1.0","summary":{"total_vms":2500,"fail":0,"warn":0,"unknown":0,"pass":2500,"evidence_completeness_pct":100},"vms":[]}'
stub=$(make_stub "audit-tier2.sh" "$tier2_json" 0)
out=$(
  EXPORTER_INTERVAL_SECONDS=600 run_collect_once "$stub"
)
assert_contains "collect_once/interval-floor-tier2 -- gauge set to 1 when 2500 VMs with 600s interval (clears tier-1's 300s, misses tier-2's 900s)" "$out" "bsod_evidence_exporter_interval_below_recommended 1"

# --- Scenario 9: interval floor -- healthy at both tiers when the interval
# is generous relative to fleet size. ---
stub=$(make_stub "audit-tier-healthy.sh" "$tier2_json" 0)
out=$(
  EXPORTER_INTERVAL_SECONDS=900 run_collect_once "$stub"
)
assert_contains "collect_once/interval-floor-healthy -- gauge stays 0 when 2500 VMs with 900s interval (meets tier-2 floor exactly)" "$out" "bsod_evidence_exporter_interval_below_recommended 0"

# --- Scenario 10 (R-27 Phase 2 / Issue K): risk-tier + finding-count metrics,
# healthy passthrough case -- assessed_count>0, so the raw vm_record.tier
# ("PASS") is emitted verbatim, not overridden. ---
tier_pass_json='{"version":"1.0","summary":{"total_vms":1,"fail":0,"warn":0,"unknown":0,"pass":9,"evidence_completeness_pct":100},"vms":[{"namespace":"win-vms","name":"win2k22-pass","evidence_completeness":100,"assessed_count":9,"unassessed_count":0,"tier":"PASS","fail_count":0,"warn_count":0}]}'
stub=$(make_stub "audit-tier-pass.sh" "$tier_pass_json" 0)
out=$(run_collect_once "$stub")
assert_contains "collect_once/tier-pass -- raw PASS tier emitted, not UNKNOWN" "$out" 'bsod_vm_risk_tier{namespace="win-vms",vm="win2k22-pass",tier="PASS"} 1'
assert_not_contains "collect_once/tier-pass -- no UNKNOWN override for an assessed VM" "$out" 'bsod_vm_risk_tier{namespace="win-vms",vm="win2k22-pass",tier="UNKNOWN"}'
assert_contains "collect_once/tier-pass -- fail finding_count is 0" "$out" 'bsod_vm_finding_count{namespace="win-vms",vm="win2k22-pass",severity="fail"} 0'
assert_contains "collect_once/tier-pass -- warn finding_count is 0" "$out" 'bsod_vm_finding_count{namespace="win-vms",vm="win2k22-pass",severity="warn"} 0'
assert_contains "collect_once/tier-pass -- unknown finding_count is 0" "$out" 'bsod_vm_finding_count{namespace="win-vms",vm="win2k22-pass",severity="unknown"} 0'
assert_contains "collect_once/tier-pass -- HELP/TYPE lines present for both new metric families" "$out" "TYPE bsod_vm_risk_tier gauge"
assert_contains "collect_once/tier-pass -- HELP/TYPE lines present for finding_count" "$out" "TYPE bsod_vm_finding_count gauge"

# --- Scenario 11 (R-27 Phase 2): the UNKNOWN override itself -- assessed_count
# is 0, so the emitted tier must be forced to UNKNOWN regardless of whatever
# risk_tier() value the stub reports (HIGH here, deliberately, to prove this
# is an override, not a passthrough of a stub that happens to already say
# UNKNOWN). A tier computed from zero evidence is not a real verdict. ---
tier_unknown_json='{"version":"1.0","summary":{"total_vms":1,"fail":0,"warn":0,"unknown":9,"pass":0,"evidence_completeness_pct":0},"vms":[{"namespace":"win-vms","name":"win2k22-blind","evidence_completeness":0,"assessed_count":0,"unassessed_count":9,"tier":"HIGH","fail_count":0,"warn_count":0}]}'
stub=$(make_stub "audit-tier-unknown.sh" "$tier_unknown_json" 0)
out=$(run_collect_once "$stub")
assert_contains "collect_once/tier-unknown-override -- assessed_count==0 forces tier=UNKNOWN" "$out" 'bsod_vm_risk_tier{namespace="win-vms",vm="win2k22-blind",tier="UNKNOWN"} 1'
assert_not_contains "collect_once/tier-unknown-override -- the stub's raw HIGH tier is never emitted" "$out" 'bsod_vm_risk_tier{namespace="win-vms",vm="win2k22-blind",tier="HIGH"}'
assert_contains "collect_once/tier-unknown-override -- unknown finding_count reflects unassessed_count" "$out" 'bsod_vm_finding_count{namespace="win-vms",vm="win2k22-blind",severity="unknown"} 9'

# --- Scenario 12 (R-27 Phase 2): finding-count values are exact passthroughs,
# and each VM emits exactly ONE active bsod_vm_risk_tier series -- the other
# five tier values must never appear at 0 for that VM (cardinality budget:
# design doc docs/design/r-27-fleet-gate-verdict-exporter.md's per-VM series
# count, not per-VM*per-tier). ---
tier_counts_json='{"version":"1.0","summary":{"total_vms":1,"fail":2,"warn":3,"unknown":1,"pass":5,"evidence_completeness_pct":91},"vms":[{"namespace":"win-vms","name":"win2k22-findings","evidence_completeness":91,"assessed_count":10,"unassessed_count":1,"tier":"CRITICAL","fail_count":2,"warn_count":3}]}'
stub=$(make_stub "audit-tier-counts.sh" "$tier_counts_json" 0)
out=$(run_collect_once "$stub")
assert_contains "collect_once/finding-counts -- fail=2" "$out" 'bsod_vm_finding_count{namespace="win-vms",vm="win2k22-findings",severity="fail"} 2'
assert_contains "collect_once/finding-counts -- warn=3" "$out" 'bsod_vm_finding_count{namespace="win-vms",vm="win2k22-findings",severity="warn"} 3'
assert_contains "collect_once/finding-counts -- unknown=1" "$out" 'bsod_vm_finding_count{namespace="win-vms",vm="win2k22-findings",severity="unknown"} 1'
_tier_series_count=$(grep -cE '^bsod_vm_risk_tier\{namespace="win-vms",vm="win2k22-findings",' <<<"$out" || true)
if [ "$_tier_series_count" -eq 1 ]; then
  echo "PASS: collect_once/finding-counts -- exactly one bsod_vm_risk_tier series for this VM (no stray 0-valued rows for inactive tiers)"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo "FAIL: collect_once/finding-counts -- expected exactly 1 bsod_vm_risk_tier series for win2k22-findings, got $_tier_series_count"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# --- Scenario 13 (R-27 Phase 2 vocabulary drift guard): risk_tier()'s only
# possible return values across BOTH the shared-config path (rs_tier() in
# scripts/lib/risk-scoring.sh) and its degraded standalone fallback must stay
# a subset of the six-value Prometheus vocabulary this exporter knows how to
# handle (UNKNOWN|PASS|CRITICAL|HIGH|MEDIUM|LOW). This is a static-analysis
# check on the SOURCE, not a stub -- it fails the moment either function
# grows a 7th literal tier string, catching drift before it ships a label no
# dashboard/alert/doc expects. See the module header's R-27 PHASE 2 TIER
# VOCABULARY note in scripts/cnv-bsod-fleet-exporter.sh. Deliberately a
# lightweight in-repo assertion, not a standalone scripts/ci/validate-*.py:
# there are only two producers of this vocabulary (both bash, in this repo),
# not the N-way, multi-language duplication that justified a generated
# shared/*.json + validator for e.g. the Windows-VM selector.
KNOWN_TIER_VOCAB="CRITICAL HIGH LOW MEDIUM PASS"
_audit_tiers=$(awk '/^risk_tier\(\) \{/,/^}/' "$SCRIPT_DIR/../scripts/cnv-win-bsod-audit.sh" | grep -oE 'echo "[A-Z_]+"' | grep -oE '[A-Z_]+' | sort -u | tr '\n' ' ' | sed 's/ $//')
_rs_tiers=$(awk '/^rs_tier\(\) \{/,/^}/' "$SCRIPT_DIR/../scripts/lib/risk-scoring.sh" | grep -oE 'echo "[A-Z_]+"' | grep -oE '[A-Z_]+' | sort -u | tr '\n' ' ' | sed 's/ $//')
if [ -n "$_audit_tiers" ] && [ "$_audit_tiers" = "$KNOWN_TIER_VOCAB" ]; then
  echo "PASS: vocabulary-drift-guard -- risk_tier()'s literal tier strings are exactly {$KNOWN_TIER_VOCAB}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo "FAIL: vocabulary-drift-guard -- risk_tier() in cnv-win-bsod-audit.sh now returns {${_audit_tiers:-<none found -- extraction broke>}}, expected exactly {$KNOWN_TIER_VOCAB}. Update scripts/cnv-bsod-fleet-exporter.sh's tier handling, this test's KNOWN_TIER_VOCAB, and the design doc's vocabulary note before widening this."
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi
# rs_tier()'s own vocabulary must be a SUBSET of risk_tier()'s (it never
# returns PASS itself -- risk_tier() adds that special case on top -- so an
# exact-match check here would be a false positive on legitimate design).
_rs_subset_ok=1
for _t in $_rs_tiers; do
  case " $KNOWN_TIER_VOCAB " in
    *" $_t "*) ;;
    *) _rs_subset_ok=0 ;;
  esac
done
if [ -n "$_rs_tiers" ] && [ "$_rs_subset_ok" -eq 1 ]; then
  echo "PASS: vocabulary-drift-guard -- rs_tier()'s literal tier strings ({$_rs_tiers}) are a subset of {$KNOWN_TIER_VOCAB}"
  PASS_COUNT=$((PASS_COUNT + 1))
else
  echo "FAIL: vocabulary-drift-guard -- rs_tier() in scripts/lib/risk-scoring.sh now returns {${_rs_tiers:-<none found -- extraction broke>}}, which is not a subset of {$KNOWN_TIER_VOCAB}"
  FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo
echo " test_bash_fleet_exporter.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
[ "$FAIL_COUNT" -eq 0 ]
