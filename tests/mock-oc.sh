#!/usr/bin/env bash
#
# mock-oc.sh
# -----------------------------------------------------------------------------
# Fake `oc` used by test_bash_gates.sh to exercise scripts/cnv-win-bsod-audit.sh
# gate logic offline (no live OCP cluster) against static JSON fixtures under
# tests/fixtures/gates/<scenario>/.
#
# Installed into PATH as `oc` (see test_bash_gates.sh) so `command -v oc` and
# every `oc ...` call in the audit script resolve here instead of a real
# cluster. MOCK_OC_FIXTURE_DIR selects which scenario's fixtures to serve.
#
# H3 (v0.16.0): MOCK_OC_FAIL_PATTERN makes selected calls FAIL (non-zero + an
# error on stderr) instead of returning fixture data, so the api-unavailable
# scenario can assert that an unreadable cluster never yields `[ OK ]`.
# Set it to an ERE matched against the full argument string; use ".*" for a
# total outage, or e.g. "get nodes|get template" for an RBAC-partial one.
#
# Handles the subset of `oc` invocations cnv-win-bsod-audit.sh actually issues:
#   - oc get vm <name> -n <ns> -o json         (per-VM fetch)
#   - oc get vm -n <ns> -o json                (namespace list mode)
#   - oc get vm -A -o json                     (all-namespaces list mode)
#   - oc get vmi <name> -n <ns> -o json        (per-VMI fetch)
#   - oc get vmi -n <ns> -o json               (namespace VMI list)
#   - oc get nodes -l ... -o json              (worker nodes)
#   - oc get clusterversion ...                (OCP version)
#   - oc get hyperconverged / kubevirt         (eviction defaults)
#   - oc get plan.forklift.konveyor.io <name> -n <ns> -o json   (MTV Plan fetch,
#     serves <fixture_dir>/plan.json -- used by test_bash_gates.sh's plan-gate
#     scenarios to drive cnv-mtv-plan-gate.sh's live-mode code path, which
#     intentionally has no offline hook of its own for the cluster-scope call)
#
# F12 (v0.17.0): the arms below are used only by
# tests/test_gather_to_analyze_e2e.sh, which drives this same mock through
# must-gather/collection-scripts/gather_virt_bsod_{pre,runtime,post} (a
# different command surface than cnv-win-bsod-audit.sh's cluster-scope/per-VM
# reads above -- debug/events/pods/single-node-get). test_bash_gates.sh never
# exercises these; it always sets BSOD_SKIP_MICROCODE_PROBE=1, which is why
# `oc debug node/...` used to be undocumented/unhandled here entirely.
#   - oc debug node/<name> --quiet -- <cmd>     (node CPU/microcode probe --
#     branches on a keyword in <cmd>: lscpu/cpuinfo/microcode; serves
#     <fixture_dir>/{lscpu,cpuinfo,microcode}.txt if present, else a canned
#     minimal value)
#   - oc get events ... -o json                (Warning/VM event timeline)
#   - oc get pods -n <ns> -l ... -o jsonpath=...  (virt-launcher pod lookup --
#     always empty: no running pod, so downstream log/domain-XML collection
#     steps no-op exactly as they would for a stopped VM on a real cluster)
#   - oc get node <name> -o json               (singular; node label lookup --
#     distinct from the plural "get nodes" worker-list arm above)
# -----------------------------------------------------------------------------
set -uo pipefail

: "${MOCK_OC_FIXTURE_DIR:?MOCK_OC_FIXTURE_DIR must point at a tests/fixtures/gates/<scenario> dir}"

# Parse args into a simplified command string for matching
args="$*"

# H3: simulate an unreadable cluster API. Must come BEFORE any dispatch so no
# fixture is served for a call the scenario declares as failing.
#
# F-07: two extra knobs make _oc_fetch's RETRY path (R-24) testable, which it
# previously was not -- the only failure this mock could produce was
# "Unauthorized", which _oc_fetch correctly classifies as permanent and never
# retries. A transient failure needs a different message and a way to stop
# failing:
#   MOCK_OC_FAIL_MESSAGE  -- override the stderr text (e.g. a 429), so the
#                            scenario chooses whether _oc_fetch sees the
#                            failure as permanent or transient.
#   MOCK_OC_FAIL_TIMES    -- fail only the first N matching calls, then serve
#                            fixtures normally. Requires MOCK_OC_FAIL_COUNTER
#                            to point at a writable counter file (the mock runs
#                            as a fresh process per call, so the count cannot
#                            live in a shell variable).
if [ -n "${MOCK_OC_FAIL_PATTERN:-}" ] && printf '%s' "$args" | grep -qE "$MOCK_OC_FAIL_PATTERN"; then
  _mock_should_fail=1
  if [ -n "${MOCK_OC_FAIL_TIMES:-}" ] && [ -n "${MOCK_OC_FAIL_COUNTER:-}" ]; then
    _mock_seen=0
    [ -f "$MOCK_OC_FAIL_COUNTER" ] && _mock_seen=$(cat "$MOCK_OC_FAIL_COUNTER" 2>/dev/null || echo 0)
    if [ "$_mock_seen" -ge "$MOCK_OC_FAIL_TIMES" ]; then
      _mock_should_fail=0
    else
      echo $((_mock_seen + 1)) > "$MOCK_OC_FAIL_COUNTER"
    fi
  fi
  if [ "$_mock_should_fail" = "1" ]; then
    echo "${MOCK_OC_FAIL_MESSAGE:-error: You must be logged in to the server (Unauthorized)}" >&2
    exit 1
  fi
fi

case "${1:-} ${2:-}" in
  "get vm")
    # Distinguish between: oc get vm <name> -n <ns> -o json  (per-VM)
    #                   and: oc get vm -n <ns> -o json        (namespace list)
    #                   and: oc get vm -A -o json             (all-namespaces)
    if echo "$args" | grep -q '\-A'; then
      # All-namespaces list mode
      if [ -f "$MOCK_OC_FIXTURE_DIR/all-vms.json" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/all-vms.json"
      elif [ -f "$MOCK_OC_FIXTURE_DIR/vm.json" ]; then
        # Wrap single VM fixture as items array
        jq '{items: [.]}' "$MOCK_OC_FIXTURE_DIR/vm.json"
      else
        echo '{"items":[]}'
      fi
    elif echo "$args" | grep -qE 'get vm -n [^ ]+ -o'; then
      # Namespace list mode (no VM name between "vm" and "-n")
      if [ -f "$MOCK_OC_FIXTURE_DIR/vms.json" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/vms.json"
      elif [ -f "$MOCK_OC_FIXTURE_DIR/vm.json" ]; then
        jq '{items: [.]}' "$MOCK_OC_FIXTURE_DIR/vm.json"
      else
        echo '{"items":[]}'
      fi
    else
      # Per-VM fetch: `oc get vm <name> -n <ns> -o json`
      if [ -f "$MOCK_OC_FIXTURE_DIR/vm.json" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/vm.json"
      else
        echo "mock-oc: no vm.json in $MOCK_OC_FIXTURE_DIR" >&2
        exit 1
      fi
    fi
    ;;
  "get vmi")
    # Namespace list mode or per-VMI fetch
    if echo "$args" | grep -qE 'get vmi -n [^ ]+ -o'; then
      # Namespace VMI list mode
      if [ -f "$MOCK_OC_FIXTURE_DIR/vmis.json" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/vmis.json"
      elif [ -f "$MOCK_OC_FIXTURE_DIR/vmi.json" ]; then
        jq '{items: [.]}' "$MOCK_OC_FIXTURE_DIR/vmi.json"
      else
        echo '{"items":[]}'
      fi
    else
      # Per-VMI fetch
      if [ -f "$MOCK_OC_FIXTURE_DIR/vmi.json" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/vmi.json"
      fi
    fi
    ;;
  "get nodes")
    # cnv-win-bsod-audit.sh's _oc_fetch always appends `-o json` here (full
    # object). F12 (v0.17.0) added gather_virt_bsod_pre/_runtime to this
    # mock's callers, and they request `-o jsonpath=...` for the SAME case
    # key -- e.g. worker node NAMES only, one per line, to iterate over.
    # Serving the full JSON blob for that request used to word-split the
    # whole document as if it were the node-name list.
    if echo "$args" | grep -q -- '-o jsonpath='; then
      # gather_virt_bsod_pre's TSC-frequency collection used to request
      # `-o jsonpath=...` here too (a dedicated branch handled it below), but
      # that lookup targeted a "scheduling.node.kubevirt.io/tsc-frequency" key
      # that KubeVirt never actually emits (confirmed live 2026-08-13 -- see
      # parsers/node_cpu_info.py's TSC_TIMER_LABEL comment). It now requests
      # `-o json` + jq instead, same as cnv-win-bsod-audit.sh's Gate 12, so
      # this arm only ever needs to serve worker node NAMES.
      if [ -f "$MOCK_OC_FIXTURE_DIR/nodes.json" ]; then
        jq -r '.items[].metadata.name' "$MOCK_OC_FIXTURE_DIR/nodes.json"
      fi
    elif [ -f "$MOCK_OC_FIXTURE_DIR/nodes.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/nodes.json"
    else
      echo '{"items":[]}'
    fi
    ;;
  "get template")
    if [ -f "$MOCK_OC_FIXTURE_DIR/templates.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/templates.json"
    else
      echo '{"items":[]}'
    fi
    ;;
  "get virtualmachineclusterinstancetype")
    if [ -f "$MOCK_OC_FIXTURE_DIR/instancetypes.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/instancetypes.json"
    else
      echo '{"items":[]}'
    fi
    ;;
  "get virtualmachineclusterpreference")
    if [ -f "$MOCK_OC_FIXTURE_DIR/preferences.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/preferences.json"
    else
      echo '{"items":[]}'
    fi
    ;;
  # Namespaced instancetypes/preferences (M-10). Distinct fixture files from
  # the cluster-scoped ones above on purpose: the audit's kind-aware resolution
  # must pick the right index, and a test where both scopes return the same
  # data could not tell a correct lookup from a wrong one.
  "get virtualmachineinstancetype")
    if [ -f "$MOCK_OC_FIXTURE_DIR/ns-instancetypes.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/ns-instancetypes.json"
    else
      echo '{"items":[]}'
    fi
    ;;
  "get virtualmachinepreference")
    if [ -f "$MOCK_OC_FIXTURE_DIR/ns-preferences.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/ns-preferences.json"
    else
      echo '{"items":[]}'
    fi
    ;;
  "get clusterversion")
    # cnv-win-bsod-audit.sh only ever requests `-o jsonpath=...` (a bare
    # version string) here, which is why this arm historically just cat'd
    # clusterversion.txt verbatim. F12 (v0.17.0) added gather_virt_bsod_pre
    # to the set of things this mock serves, and it requests `-o json` (a
    # full ClusterVersion object) for the SAME case key -- so the two
    # requested shapes must be told apart, not just the verb+resource.
    #
    # N.B. check jsonpath FIRST: "-o json" is a substring of "-o jsonpath=",
    # so testing for "-o json" first would misclassify every jsonpath call
    # (confirmed live: it silently fed a JSON object where cnv-win-bsod-audit.sh
    # expected a bare version string, corrupting its OCP-version-gated logic
    # across several unrelated gate scenarios in test_bash_gates.sh).
    if echo "$args" | grep -q -- '-o jsonpath='; then
      if [ -f "$MOCK_OC_FIXTURE_DIR/clusterversion.txt" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/clusterversion.txt"
      fi
    elif echo "$args" | grep -q -- '-o json'; then
      if [ -f "$MOCK_OC_FIXTURE_DIR/clusterversion.json" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/clusterversion.json"
      elif [ -f "$MOCK_OC_FIXTURE_DIR/clusterversion.txt" ]; then
        jq -Rn --rawfile v "$MOCK_OC_FIXTURE_DIR/clusterversion.txt" \
          '{status: {desired: {version: ($v | gsub("\\s+$"; ""))}}}'
      else
        echo '{}'
      fi
    else
      if [ -f "$MOCK_OC_FIXTURE_DIR/clusterversion.txt" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/clusterversion.txt"
      fi
    fi
    ;;
  "get hyperconverged"|"get kubevirt")
    :
    ;;
  "get plan.forklift.konveyor.io"|"get plan")
    # `oc get plan.forklift.konveyor.io <name> -n <ns> -o json`
    if [ -f "$MOCK_OC_FIXTURE_DIR/plan.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/plan.json"
    else
      echo "mock-oc: no plan.json in $MOCK_OC_FIXTURE_DIR" >&2
      exit 1
    fi
    ;;
  "get csv")
    echo '{}'
    ;;
  "get events")
    if [ -f "$MOCK_OC_FIXTURE_DIR/events.json" ]; then
      cat "$MOCK_OC_FIXTURE_DIR/events.json"
    else
      echo '{"items":[]}'
    fi
    ;;
  "get pods")
    # Intentionally always empty (not even '{"items":[]}'): the real call is
    # `-o jsonpath='{.items[0].metadata.name}'`, which yields an empty string
    # for a no-match, not a JSON blob. Returning JSON text here would make the
    # caller's `pod=$(oc get pods ...)` non-empty and misinterpret it as a pod
    # name, breaking the "no running virt-launcher found" skip path.
    ;;
  "get node")
    # Singular -- `oc get node <name> -o json` (label lookup), distinct from
    # the plural "get nodes" worker-list arm above. Serves the first entry of
    # nodes.json regardless of which <name> was requested; fixtures needing
    # more than one distinct per-node identity should add a dedicated file.
    if [ -f "$MOCK_OC_FIXTURE_DIR/nodes.json" ]; then
      jq '.items[0] // {}' "$MOCK_OC_FIXTURE_DIR/nodes.json"
    else
      echo '{}'
    fi
    ;;
  "debug node/"*)
    # `oc debug node/<name> --quiet -- <cmd...>` -- branch on a keyword in the
    # trailing <cmd> rather than parsing it positionally, since the collectors
    # and Gate 8's live microcode probe each wrap a different command (chroot
    # lscpu / cat proc/cpuinfo / a microcode-reading one-liner) after the same
    # `debug node/<name> --quiet --` prefix.
    if echo "$args" | grep -q 'lscpu'; then
      if [ -f "$MOCK_OC_FIXTURE_DIR/lscpu.txt" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/lscpu.txt"
      else
        echo "Architecture: x86_64"
      fi
    elif echo "$args" | grep -q 'cpuinfo'; then
      if [ -f "$MOCK_OC_FIXTURE_DIR/cpuinfo.txt" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/cpuinfo.txt"
      else
        echo "model name	: Mock CPU"
      fi
    elif echo "$args" | grep -qi 'microcode'; then
      if [ -f "$MOCK_OC_FIXTURE_DIR/microcode.txt" ]; then
        cat "$MOCK_OC_FIXTURE_DIR/microcode.txt"
      else
        echo "0xffffffff"
      fi
    fi
    ;;
  *)
    echo "mock-oc: unhandled invocation: oc $*" >&2
    exit 1
    ;;
esac
