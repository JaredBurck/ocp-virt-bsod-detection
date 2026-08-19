#!/usr/bin/env bash
#
# stub-oc-fleet.sh
# -----------------------------------------------------------------------------
# Minimal mock `oc` used only by tests/test_fleet_readiness.sh to drive
# cnv-mtv-fleet-readiness.sh / cnv-mtv-plan-gate.sh through their *live-mode*
# code path (no MTV_PLAN_JSON/FLEET_PLAN_DIR) -- this is required because
# cnv-mtv-plan-gate.sh intentionally skips its cluster-scope BSOD_CHECK_CMD
# call whenever MTV_PLAN_JSON is set (offline/test mode), so the
# FLEET_PLAN_DIR hook alone cannot exercise the cluster-scope aggregation
# fix under test. Combined with tests/stub-bsod-check.sh (BSOD_CHECK_CMD),
# this lets both plan enumeration and cluster-scope/per-VM outcomes be
# scripted entirely from fixtures, with no live cluster involved.
#
# Understands only the exact `oc` invocations cnv-mtv-fleet-readiness.sh and
# cnv-mtv-plan-gate.sh make:
#   oc get plan.forklift.konveyor.io -n <ns> -o jsonpath=...      (enumerate)
#   oc get plan.forklift.konveyor.io <name> -n <ns> -o json       (fetch)
#   oc get vm <name> -n <ns>                                      (existence)
#
# Env:
#   STUB_PLAN_NAMES   space-separated plan names to report on enumeration
#   STUB_PLAN_DIR     dir containing <name>.json for each plan (note: this
#                      is intentionally a *different* env var than
#                      stub-bsod-check.sh's STUB_FIXTURES_DIR -- the two
#                      stubs are independent and read from separate trees)
# -----------------------------------------------------------------------------
set -uo pipefail

if [ "${1:-}" = "get" ] && [ "${2:-}" = "plan.forklift.konveyor.io" ]; then
  # Enumeration form: `get plan.forklift.konveyor.io -n <ns> -o jsonpath=...`
  if [ "${3:-}" = "-n" ]; then
    for name in ${STUB_PLAN_NAMES:-}; do
      printf '%s\n' "$name"
    done
    exit 0
  fi
  # Fetch form: `get plan.forklift.konveyor.io <name> -n <ns> -o json`
  name="${3:-}"
  f="${STUB_PLAN_DIR:?STUB_PLAN_DIR must be set}/$name.json"
  if [ -f "$f" ]; then cat "$f"; exit 0; fi
  echo "stub-oc-fleet.sh: no fixture for plan '$name'" >&2
  exit 1
fi

if [ "${1:-}" = "get" ] && [ "${2:-}" = "vm" ]; then
  # Existence probe only -- fleet/plan gate discard stdout, check exit code.
  exit 0
fi

echo "stub-oc-fleet.sh: unrecognized invocation: $*" >&2
exit 2
