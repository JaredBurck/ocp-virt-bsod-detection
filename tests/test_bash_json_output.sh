#!/usr/bin/env bash
#
# test_bash_json_output.sh
# -----------------------------------------------------------------------------
# Validates the --json and --json=ndjson output modes of cnv-win-bsod-audit.sh
# against known fixture scenarios. Ensures:
#   - Output is valid JSON (parseable by jq)
#   - Required top-level fields exist in single-doc mode
#   - Each finding object has the expected schema
#   - NDJSON mode emits one valid JSON per line with a summary trailer
#
# Uses the same mock-oc.sh + fixture infrastructure as test_bash_gates.sh.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_SCRIPT="$REPO_ROOT/scripts/cnv-win-bsod-audit.sh"
FIXTURES_DIR="$SCRIPT_DIR/fixtures/gates"
NS="bsod-test"

PASS_COUNT=0
FAIL_COUNT=0

MOCK_BIN_DIR="$(mktemp -d)"
cp "$SCRIPT_DIR/mock-oc.sh" "$MOCK_BIN_DIR/oc"
chmod +x "$MOCK_BIN_DIR/oc"
cleanup() { rm -rf "$MOCK_BIN_DIR"; }
trap cleanup EXIT

run_json_test() {
  local scenario="$1" vm_name="$2" label="$3"
  shift 3
  local extra_args=("$@")

  local fixture_dir="$FIXTURES_DIR/$scenario"
  local guest_evidence_dir="$fixture_dir/no-such-guest-evidence"
  [ -d "$fixture_dir/guest-evidence" ] && guest_evidence_dir="$fixture_dir/guest-evidence"

  local out
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_OC_RETRIES=0 \
        BSOD_GUEST_EVIDENCE_DIR="$guest_evidence_dir" \
        "$AUDIT_SCRIPT" "${extra_args[@]}" "$NS" "$vm_name" 2>&1)
  local rc=$?

  echo "$out"
  return $rc
}

assert_json_field() {
  local json="$1" field="$2" label="$3"
  if ! echo "$json" | jq -e "$field" >/dev/null 2>&1; then
    echo "FAIL: $label -- missing field: $field"
    FAIL_COUNT=$((FAIL_COUNT+1))
    return 1
  fi
  return 0
}

# --- Test: single-doc JSON output for good scenario ---
echo "=== Test: --json single-doc (good scenario) ==="
json_out=$(run_json_test good win2k22-good "json-good" --json)

if echo "$json_out" | jq . >/dev/null 2>&1; then
  echo "  valid JSON: yes"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: json-good -- output is not valid JSON"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

assert_json_field "$json_out" '.version' "json-good .version" && PASS_COUNT=$((PASS_COUNT+1))
assert_json_field "$json_out" '.timestamp' "json-good .timestamp" && PASS_COUNT=$((PASS_COUNT+1))
assert_json_field "$json_out" '.cluster_scope' "json-good .cluster_scope" && PASS_COUNT=$((PASS_COUNT+1))
assert_json_field "$json_out" '.vms' "json-good .vms" && PASS_COUNT=$((PASS_COUNT+1))
assert_json_field "$json_out" '.summary' "json-good .summary" && PASS_COUNT=$((PASS_COUNT+1))
assert_json_field "$json_out" '.summary.total_vms' "json-good .summary.total_vms" && PASS_COUNT=$((PASS_COUNT+1))
assert_json_field "$json_out" '.namespaces' "json-good .namespaces" && PASS_COUNT=$((PASS_COUNT+1))

# Check VM findings structure
vm_findings=$(echo "$json_out" | jq '.vms[0].findings // []')
finding_count=$(echo "$vm_findings" | jq 'length')
if [ "$finding_count" -gt 0 ]; then
  first_finding=$(echo "$vm_findings" | jq '.[0]')
  assert_json_field "$first_finding" '.gate' "json-good finding.gate" && PASS_COUNT=$((PASS_COUNT+1))
  assert_json_field "$first_finding" '.severity' "json-good finding.severity" && PASS_COUNT=$((PASS_COUNT+1))
  assert_json_field "$first_finding" '.message' "json-good finding.message" && PASS_COUNT=$((PASS_COUNT+1))
  assert_json_field "$first_finding" '.stop_code' "json-good finding.stop_code" && PASS_COUNT=$((PASS_COUNT+1))
else
  echo "  (no non-OK findings to validate schema -- skipping field checks)"
fi

# --- Test: single-doc JSON output for bad scenario ---
echo ""
echo "=== Test: --json single-doc (bad scenario) ==="
json_out=$(run_json_test bad win2k22-bad "json-bad" --json)

if echo "$json_out" | jq . >/dev/null 2>&1; then
  echo "  valid JSON: yes"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: json-bad -- output is not valid JSON"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

fail_count=$(echo "$json_out" | jq '.summary.fail // 0')
if [ "$fail_count" -gt 0 ]; then
  echo "  summary.fail=$fail_count (expected > 0)"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: json-bad -- expected summary.fail > 0, got $fail_count"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# --- Test: NDJSON streaming output ---
echo ""
echo "=== Test: --json=ndjson (good scenario) ==="
ndjson_out=$(run_json_test good win2k22-good "ndjson-good" --json=ndjson)

ndjson_ok=1
while IFS= read -r line; do
  [ -z "$line" ] && continue
  if ! echo "$line" | jq . >/dev/null 2>&1; then
    echo "FAIL: ndjson-good -- invalid JSON line: $line"
    ndjson_ok=0
    break
  fi
done <<< "$ndjson_out"

if [ "$ndjson_ok" -eq 1 ]; then
  echo "  all lines valid JSON: yes"
  PASS_COUNT=$((PASS_COUNT+1))
else
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# Check for summary line
summary_line=$(echo "$ndjson_out" | grep '"type":"summary"' || echo "$ndjson_out" | jq -c 'select(.type == "summary")' 2>/dev/null || true)
if [ -n "$summary_line" ]; then
  echo "  summary line present: yes"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: ndjson-good -- no summary line found"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# --- Test: N3 -- summary.unknown / cluster_scope.unknown_count must not be
# dropped. "good" scenario has 4 [UNKN] lines (Gate10 multiqueue-unconfirmed +
# Gate15/16 per-VM + Gate20 cluster-scope), so this also proves the field is
# not just present-but-zero. R-06 added the Gate 10 UNKNOWN: blockMultiQueue is
# unset on this fixture and the cluster API cannot read the running queue
# configuration, which previously WARNed as "implicit multiqueue". ---
echo ""
echo "=== Test: N3 -- unknown_count surfaced in --json doc mode (good scenario) ==="
json_out=$(run_json_test good win2k22-good "json-unknown" --json)

assert_json_field "$json_out" '.summary.unknown' "json-unknown .summary.unknown" && PASS_COUNT=$((PASS_COUNT+1))
assert_json_field "$json_out" '.cluster_scope.unknown_count' "json-unknown .cluster_scope.unknown_count" && PASS_COUNT=$((PASS_COUNT+1))

summary_unknown=$(echo "$json_out" | jq '.summary.unknown // -1')
if [ "$summary_unknown" -eq 4 ]; then
  echo "  summary.unknown=$summary_unknown (expected 4)"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: json-unknown -- expected summary.unknown=4, got $summary_unknown"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# --- Test: N3 -- same field must survive ndjson mode's summary line ---
echo ""
echo "=== Test: N3 -- unknown surfaced in --json=ndjson summary line (good scenario) ==="
ndjson_out=$(run_json_test good win2k22-good "ndjson-unknown" --json=ndjson)
ndjson_summary=$(echo "$ndjson_out" | jq -c 'select(.type == "summary")' 2>/dev/null || true)

if echo "$ndjson_summary" | jq -e '.unknown' >/dev/null 2>&1; then
  ndjson_unknown=$(echo "$ndjson_summary" | jq '.unknown')
  if [ "$ndjson_unknown" -eq 4 ]; then
    echo "  ndjson summary.unknown=$ndjson_unknown (expected 3)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "FAIL: ndjson-unknown -- expected .unknown=4, got $ndjson_unknown"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
else
  echo "FAIL: ndjson-unknown -- summary line missing .unknown field"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# --- Test: --json with --stop-code filtering ---
echo ""
echo "=== Test: --json with --stop-code 0x4E (good scenario) ==="
json_out=$(run_json_test good win2k22-good "json-stop-code" --json --stop-code 0x4E)

if echo "$json_out" | jq . >/dev/null 2>&1; then
  echo "  valid JSON with stop-code filter: yes"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: json-stop-code -- output is not valid JSON"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo
echo "=============================================="
echo " test_bash_json_output.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
