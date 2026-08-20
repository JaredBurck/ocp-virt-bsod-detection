#!/usr/bin/env bash
#
# test_bash_gates.sh
# -----------------------------------------------------------------------------
# Fixture-driven regression harness for scripts/cnv-win-bsod-audit.sh's gate
# logic. Runs entirely offline: `oc` is replaced with mock-oc.sh, which serves
# static JSON fixtures from tests/fixtures/gates/<scenario>/ instead of
# talking to a live OCP cluster. This lets the bash gate PASS/WARN/FAIL
# decision logic be regression-tested in CI without cluster credentials
# (previously only exercised live via tests/bsod-test-vms.yaml against a real
# cluster -- see tests/README.md).
#
# Each fixture scenario is one VM spec (+ optional VMI/nodes) with a hand
# -verified expected [FAIL]/[WARN] line count and exit code (derived by
# reading the gate logic in scripts/cnv-win-bsod-audit.sh directly -- see the
# per-scenario comments below run_case calls). BSOD_SKIP_MICROCODE_PROBE=1 is
# always set so Gate 8 never shells out to `oc debug` (mock-oc.sh does not
# implement it).
#
# Usage: tests/test_bash_gates.sh
# Exit code: 0 if every case matches its expected FAIL/WARN/exit, else 1.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_SCRIPT="$REPO_ROOT/scripts/cnv-win-bsod-audit.sh"
FIXTURES_DIR="$SCRIPT_DIR/fixtures/gates"
NS="bsod-test"

if [ ! -x "$AUDIT_SCRIPT" ]; then
  echo "FAIL: $AUDIT_SCRIPT not found or not executable"
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: jq is required (cnv-win-bsod-audit.sh depends on it)"
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

# Isolated PATH dir containing only our mock `oc` -- never shadows/mutates a
# real `oc` that might also be on PATH.
MOCK_BIN_DIR="$(mktemp -d)"
cp "$SCRIPT_DIR/mock-oc.sh" "$MOCK_BIN_DIR/oc"
chmod +x "$MOCK_BIN_DIR/oc"
cleanup() { rm -rf "$MOCK_BIN_DIR"; }
trap cleanup EXIT

# run_case <scenario> <vm> <expect_fail> <expect_warn> <expect_exit> [expect_unknown] [flags...]
# expect_unknown counts [UNKN] lines -- gates that could not be evaluated because
# required evidence was absent. Defaults to 0. It is asserted separately from
# WARN on purpose: "we found a risk" and "we could not look" must never be
# allowed to substitute for one another in a migration gate.
run_case() {
  local scenario="$1" vm_name="$2" expect_fail="$3" expect_warn="$4" expect_exit="$5"
  shift 5
  local expect_unknown=0
  if [ "${1:-}" -eq "${1:-}" ] 2>/dev/null; then expect_unknown="$1"; shift; fi
  local extra_args=("$@")

  local fixture_dir="$FIXTURES_DIR/$scenario"
  if [ ! -f "$fixture_dir/vm.json" ]; then
    echo "FAIL: $scenario -- missing fixture $fixture_dir/vm.json"
    FAIL_COUNT=$((FAIL_COUNT+1))
    return
  fi

  local label="$scenario"
  [ "${#extra_args[@]}" -gt 0 ] && label="$scenario (${extra_args[*]})"

  # Determine guest evidence dir (for Gate 15/16 testing)
  local guest_evidence_dir="$fixture_dir/no-such-guest-evidence"
  if [ -d "$fixture_dir/guest-evidence" ]; then
    guest_evidence_dir="$fixture_dir/guest-evidence"
  fi

  # H3: a scenario may declare `oc` calls that must FAIL, via a fail-pattern
  # file. Used by the api-unavailable scenario to prove an unreadable cluster
  # never yields a passing verdict.
  local fail_pattern=""
  if [ -f "$fixture_dir/oc-fail-pattern.txt" ]; then
    fail_pattern=$(head -1 "$fixture_dir/oc-fail-pattern.txt")
  fi

  local out actual_exit
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        MOCK_OC_FAIL_PATTERN="$fail_pattern" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        BSOD_GUEST_EVIDENCE_DIR="$guest_evidence_dir" \
        "$AUDIT_SCRIPT" "${extra_args[@]}" "$NS" "$vm_name" 2>&1)
  actual_exit=$?

  # H3 invariant (TOTAL outage only): if literally every `oc` call failed, no
  # check has any evidence, so NOT ONE may report a pass. Before v0.16.0 this
  # produced exit 0 and six `[ OK ]` verdicts.
  #
  # Deliberately NOT applied to partial outages: when `oc get vm` succeeds but
  # cluster-scoped reads are denied, per-VM checks that read only the VM's own
  # spec (boot-disk bus, machine type, hyperv block...) remain legitimately
  # assessable and SHOULD still pass. For those scenarios the fixture supplies
  # must-not-contain.txt naming the specific conclusions that would be
  # unfounded.
  if [ "$fail_pattern" = ".*" ]; then
    local leaked_ok
    leaked_ok=$(grep -c '\[ OK \]' <<<"$out" || true)
    if [ "$leaked_ok" -ne 0 ]; then
      echo "FAIL: $label -- API fully unreadable but $leaked_ok [ OK ] verdict(s) emitted:"
      grep '\[ OK \]' <<<"$out" | sed 's/^/        /'
      FAIL_COUNT=$((FAIL_COUNT+1))
      return
    fi
  fi

  # Per-scenario forbidden conclusions: verdicts that would be unfounded given
  # what this scenario made unreadable.
  if [ -f "$fixture_dir/must-not-contain.txt" ]; then
    local _bad_line _violated=0
    while IFS= read -r _bad_line; do
      [ -z "$_bad_line" ] && continue
      if grep -qF "$_bad_line" <<<"$out"; then
        echo "FAIL: $label -- emitted a conclusion its evidence cannot support:"
        echo "        $(grep -F "$_bad_line" <<<"$out" | head -1)"
        _violated=1
      fi
    done < "$fixture_dir/must-not-contain.txt"
    if [ "$_violated" -eq 1 ]; then
      FAIL_COUNT=$((FAIL_COUNT+1))
      return
    fi
  fi

  local actual_fail actual_warn actual_unknown
  actual_fail=$(grep -c '\[FAIL\]' <<<"$out" || true)
  actual_warn=$(grep -c '\[WARN\]' <<<"$out" || true)
  actual_unknown=$(grep -c '\[UNKN\]' <<<"$out" || true)

  local ok=1
  if [ "$actual_fail" -ne "$expect_fail" ]; then
    echo "FAIL: $label -- expected $expect_fail [FAIL] line(s), got $actual_fail"
    ok=0
  fi
  if [ "$actual_warn" -ne "$expect_warn" ]; then
    echo "FAIL: $label -- expected $expect_warn [WARN] line(s), got $actual_warn"
    ok=0
  fi
  if [ "$actual_unknown" -ne "$expect_unknown" ]; then
    echo "FAIL: $label -- expected $expect_unknown [UNKN] line(s), got $actual_unknown"
    ok=0
  fi
  if [ "$actual_exit" -ne "$expect_exit" ]; then
    echo "FAIL: $label -- expected exit code $expect_exit, got $actual_exit"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (FAIL=$actual_fail WARN=$actual_warn UNKN=$actual_unknown exit=$actual_exit)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out"
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

# run_case_json <scenario> <vm> <expect_exit> <expect_tier> <expect_fail_count> <expect_warn_count> [extra_args...]
# like run_case but validates JSON output is parseable. expect_tier/
# expect_fail_count/expect_warn_count are vm_record's own tier/fail_count/
# warn_count fields (R-27 Phase 2) -- exact values, hand-verified against a
# live run of this fixture; a regression here would ship silently, since
# scripts/cnv-bsod-fleet-exporter.sh reads exactly these fields for
# bsod_vm_risk_tier/bsod_vm_finding_count.
run_case_json() {
  local scenario="$1" vm_name="$2" expect_exit="$3" expect_tier="$4" \
        expect_fail_count="$5" expect_warn_count="$6"
  shift 6
  local extra_args=("$@")

  local fixture_dir="$FIXTURES_DIR/$scenario"
  local label="$scenario (--json ${extra_args[*]:-})"

  local guest_evidence_dir="$fixture_dir/no-such-guest-evidence"
  if [ -d "$fixture_dir/guest-evidence" ]; then
    guest_evidence_dir="$fixture_dir/guest-evidence"
  fi

  local out actual_exit
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        BSOD_GUEST_EVIDENCE_DIR="$guest_evidence_dir" \
        "$AUDIT_SCRIPT" --json "${extra_args[@]}" "$NS" "$vm_name" 2>&1)
  actual_exit=$?

  local ok=1
  if [ "$actual_exit" -ne "$expect_exit" ]; then
    echo "FAIL: $label -- expected exit code $expect_exit, got $actual_exit"
    ok=0
  fi
  # Validate JSON
  if ! echo "$out" | jq . >/dev/null 2>&1; then
    echo "FAIL: $label -- output is not valid JSON"
    ok=0
  fi
  # Check required fields
  if ! echo "$out" | jq -e '.version' >/dev/null 2>&1; then
    echo "FAIL: $label -- missing .version field"
    ok=0
  fi
  if ! echo "$out" | jq -e '.summary' >/dev/null 2>&1; then
    echo "FAIL: $label -- missing .summary field"
    ok=0
  fi
  # Issue K (R-21 follow-through): evidence completeness must be present and
  # in-range at both the fleet-summary and per-VM levels, and every VM record
  # must carry an unassessed_count alongside it. A regression here would ship
  # silently -- scripts/cnv-bsod-fleet-exporter.sh reads exactly these
  # fields and would start serving stale/zero metrics with no error anywhere.
  if ! echo "$out" | jq -e '.summary.evidence_completeness_pct | numbers and (. >= 0 and . <= 100)' >/dev/null 2>&1; then
    echo "FAIL: $label -- .summary.evidence_completeness_pct missing or out of [0,100] range"
    ok=0
  fi
  if ! echo "$out" | jq -e '.vms[0].evidence_completeness | numbers and (. >= 0 and . <= 100)' >/dev/null 2>&1; then
    echo "FAIL: $label -- .vms[0].evidence_completeness missing or out of [0,100] range"
    ok=0
  fi
  if ! echo "$out" | jq -e '.vms[0].unassessed_count | numbers and (. >= 0)' >/dev/null 2>&1; then
    echo "FAIL: $label -- .vms[0].unassessed_count missing or negative"
    ok=0
  fi
  # R-27 Phase 2 (Issue K): tier/fail_count/warn_count are the exporter's
  # bsod_vm_risk_tier/bsod_vm_finding_count source fields -- assert both
  # presence/vocabulary AND the exact expected values, not just "is a number".
  local actual_tier actual_fail_count actual_warn_count
  actual_tier=$(echo "$out" | jq -r '.vms[0].tier // "MISSING"')
  actual_fail_count=$(echo "$out" | jq -r '.vms[0].fail_count // "MISSING"')
  actual_warn_count=$(echo "$out" | jq -r '.vms[0].warn_count // "MISSING"')
  case "$actual_tier" in
    PASS|CRITICAL|HIGH|MEDIUM|LOW) ;;
    *)
      echo "FAIL: $label -- .vms[0].tier '$actual_tier' is not one of PASS|CRITICAL|HIGH|MEDIUM|LOW (risk_tier()'s only possible outputs)"
      ok=0
      ;;
  esac
  if [ "$actual_tier" != "$expect_tier" ]; then
    echo "FAIL: $label -- expected .vms[0].tier '$expect_tier', got '$actual_tier'"
    ok=0
  fi
  if [ "$actual_fail_count" != "$expect_fail_count" ]; then
    echo "FAIL: $label -- expected .vms[0].fail_count $expect_fail_count, got $actual_fail_count"
    ok=0
  fi
  if [ "$actual_warn_count" != "$expect_warn_count" ]; then
    echo "FAIL: $label -- expected .vms[0].warn_count $expect_warn_count, got $actual_warn_count"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (exit=$actual_exit, valid JSON)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out" | head -20
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

#           scenario         vm name          FAIL WARN EXIT  [extra args]

# win2k22-good (tests/bsod-test-vms.yaml VM 3) on 2 Intel/no-AMD nodes with
# consistent TSC. Gate10 WARNs (2 vCPUs + virtio disk => implicit multiqueue,
# guest driver unconfirmed), Gate15 WARNs (no guest evidence dir), and Gate16
# WARNs (phantom NIC status unknown) are expected even for an otherwise
# well-configured VM -- both require guest-side confirmation.
run_case good win2k22-good 0 1 0 4

# F-03: at-stream-max must score in the weight-0 `platform` domain (gate 22).
#
# This scenario was previously UNREACHABLE in the gate tests. Only 7 fixtures
# carry clusterversion.txt at all, so STREAM/STREAM_MAX were empty everywhere
# and driver-verdict.sh's ceiling branch never fired -- the scoring change was
# covered by the shared vectors but never end to end.
#
# OCP 4.18.26 -> el9_4 (ceiling 1.9.46) with a guest reporting exactly 1.9.46.
# Same shape as `good` otherwise, and the ceiling WARN replaces `good`'s
# Gate 15 UNKNOWN -- guest evidence now exists, so that check is assessed.
run_case stream-capped-el9-4 win2k22-good 0 2 0 1

# win2k22-bad (tests/bsod-test-vms.yaml VM 7): sata boot disk (Gate1), e1000e
# NIC (Gate3), unset cpu.model (Gate4), no hyperv block (Gate5),
# evictionStrategy=None (Gate6, hard FAIL), plus the always-on Gate15 and
# Gate16 guest-evidence UNKNs. Same no-AMD node fixture.
# Gate 14 does NOT warn on sockets=4 here: L-15 made the 2-socket cap
# Desktop-edition-only. Windows Server 2022 is licensed per physical core with
# no socket cap, so a 4-socket Server VM is a legitimate topology; the old
# unconditional WARN was a false positive on every multi-socket Server guest.
run_case bad            win2k22-bad       1 4 1 3

# L-15 positive case: the Desktop-edition socket cap must still fire. Same clean
# spec as `good` but os=windows11 with sockets=4. Gate14 WARNs (Desktop 10/11
# hard-caps at 2 sockets, so 2 of the 4 vCPUs are silently unused) and Gate10
# WARNs (4 vCPUs + virtio disk => implicit multiqueue). Paired with the `bad`
# case above, this pins BOTH sides of the edition branch: without it, deleting
# the Desktop check entirely would still leave the suite green.
run_case desktop-oversocket win11-oversocket 0 2 0 4

# Master remediation plan (Phase 3): Windows-VM detection extended to
# Win7/8.1/XP. This VM has NO vm.kubevirt.io/os annotation/label, no
# template label, and no hyperv block -- the ONLY thing that can identify it
# as Windows is the new "xp" name-fallback suffix word added to
# _WIN_NAME_RE's jq mirror (winxp-legacy wasn't detected at all before this
# change: "win" followed immediately by the letter "x" doesn't match the
# pattern's bare [^a-z]/[0-9]/$ terminator). If this scenario is reached at
# all (i.e. it doesn't silently disappear from the audit), detection works.
# Gate20 (cluster-scope) WARNs (no OS annotation => alert-invisible), the
# per-VM "OS not annotated" WARN fires, Gate5 WARNs (no hyperv block), Gate10
# WARNs (virtio-blk + multi-vCPU => implicit multiqueue), Gate21 WARNs (master
# remediation plan Phase 4: virtio boot disk + no virtio-win containerDisk
# ever attached, matching this VM's real bsod-test-vms.yaml definition), PLUS
# (Issue I) Gate20's new PER-VM component WARNs a second time for the exact
# same underlying gap -- the cluster-scope block reports the fleet-wide
# aggregate, the per-VM block now also puts the finding on this VM's own
# verdict line so it isn't only visible via a separate list, per Issue I's
# acceptance criteria. Plus the always-on Gate15/Gate16/Gate20-OCP-version
# UNKNs.
run_case legacy-client-name-fallback winxp-legacy 0 6 0 4

# Master remediation plan (Phase 3): win7-oversocket carries os="win7" (the
# new win7 alternative in the OS-hint jq regex) and sockets=4. This also
# regression-tests the companion Gate14 fix in the SAME phase: the
# Desktop-vs-Server edition classifier previously only recognized
# win10/win11 as Desktop editions, so a legacy-client VM with >2 sockets
# fell into the "unknown edition" WARN branch instead of correctly getting
# the Desktop 2-socket-cap WARN. Gate14 must now WARN with the SAME message
# desktop-oversocket gets (not the unknown-edition text). Gate10 WARNs (4
# vCPUs + virtio disk => implicit multiqueue). N-06 (Wave 7, R-47): Gate15's
# new evaluate_guest_os_driver_compatibility also WARNs for os="win7" now
# (KCS 4234591 -- Windows 7 is not a Red Hat Certified OpenShift
# Virtualization guest OS at all, independent of the socket-count finding
# above), so this scenario went from 1 WARN to 2. Plus Gate15's OWN
# "guest_ver not available" UNKN and Gate16/Gate20-OCP UNKNs as usual.
run_case legacy-client-oversocket win7-oversocket 0 3 0 4

# Master remediation plan (Phase 4): new Gate 21 (virtio-win driver-source-
# attached) isolated scenario. Otherwise identical to win2k22-good (Gate10
# WARNs on 2 vCPUs + virtio disk => implicit multiqueue) but with NO
# virtiocontainerdisk (or any other virtio-win-named) volume attached at
# all -- Gate21 WARNs since no guest evidence confirms a driver is already
# installed either. Gate15/Gate16/Gate20-OCP-version UNKN as usual.
run_case no-driver-source win2k22-no-driver-source 0 2 0 4

# win2k22-good VM against a single AMD node with no cpu-family label. Gate8's
# "unknown family" branch emits [UNKN] (H-8 + Phase 2): AMD nodes are present
# but Family 1Ah can be neither ruled in nor out, so reporting [ OK ] would
# clear a KCS-7132511 (0x4E) risk on evidence that was never collected -- and
# reporting [WARN] would overstate it as a found risk. Per-VM Gate9 WARNs
# (arch-capabilities not disabled) plus Gate10/Gate15/Gate16 as in `good`.
#
# v0.17.0 (F3): cluster-scope Gate9's "AMD nodes present" line was downgraded
# warn()->info() -- it was a redundant pointer to this same per-VM check, so
# it could never itself be resolved (every AMD fleet has AMD nodes by
# definition). WARN count here drops from 3 to 2 (cluster line no longer
# counts); the per-VM Gate9 WARN below is completely unaffected.
run_case amd-nodes win2k22-good 0 2 0 5

# Same fixture as amd-nodes, but --strict promotes the two warn_strict()
# -guarded per-VM findings (Gate9 arch-capabilities, Gate10 multiqueue) to
# FAILs. Gate15/Gate16 use plain warn() and are NOT promoted.
# Gate8's unknown-family [UNKN] is likewise unaffected by --strict: --strict
# promotes known risks, it cannot manufacture evidence that was never collected.
#
# v0.17.0 (F3): WARN count here drops from 1 to 0 -- the cluster Gate9 line
# that used to be the sole surviving (non-promoted) WARN under --strict is
# now info(), not warn(), so it was never eligible for promotion or counting
# in the first place. FAIL=2 and exit=1 are unaffected.
run_case amd-nodes win2k22-good 1 1 1 5 --strict

# win2k22-good VM against a single AMD Family 1Ah node (cpu-family=26).
# BSOD_SKIP_MICROCODE_PROBE=1 forces Gate8's "microcode probe skipped" WARN
# (mock-oc.sh doesn't implement `oc debug`) instead of FAIL/OK. Per-VM Gate9
# (arch-capabilities not disabled) and Gate10 (multiqueue) also WARN.
#
# v0.17.0 (F3): WARN count drops from 4 to 3 -- cluster-scope Gate9's "AMD
# nodes present" pointer line is now info(), not warn().
run_case amd-family1a win2k22-good 0 3 0 4

# win2k22-good VM on 2 non-AMD nodes with different tsc-frequency labels ->
# Gate12 WARNs on the mismatch; no AMD-related warnings fire.
run_case tsc-mismatch win2k22-good 0 2 0 4

# Regression coverage for the 2026-08-13 live-cluster bug fix: KubeVirt never
# emits a bare "scheduling.node.kubevirt.io/tsc-frequency" key (confirmed live
# -- see parsers/node_cpu_info.py's TSC_TIMER_LABEL comment and CLAUDE.md's
# KubeVirt Label Format section). These three exercise the real key shapes
# Gate 12 must now handle, none of which the old exact-bare-key lookup could
# ever have matched on a live cluster.

# No cpu-timer.node.kubevirt.io/tsc-frequency label at all, but each node
# carries exactly ONE scheduling.node.kubevirt.io/tsc-frequency-<value> label
# with the SAME value -> unambiguous fallback -> Gate12 reports consistent.
run_case tsc-scheduling-fallback win2k22-good 0 1 0 4

# No cpu-timer label, and each node carries TWO DISTINCT
# scheduling.node.kubevirt.io/tsc-frequency-<value> labels (tsc-scalable=true,
# i.e. compatible with more than one bucket) -> cannot tell which is this
# node's own frequency, so the fallback correctly refuses to guess and Gate12
# treats this the same as "absent" (WARN, since the VM uses HyperV
# Reenlightenment) rather than fabricating a PASS or a WARN from noise.
run_case tsc-ambiguous-scheduling win2k22-good 0 2 0 4

# Reproduces the exact live label combination found on a real 3-node Intel
# cluster (k0nul3aa, 2026-08-13): cpu-timer.node.kubevirt.io/tsc-frequency
# present on every node (genuinely different values -- worker-1 is ~27ppm off
# from workers 2/3) PLUS multiple scheduling.node.kubevirt.io/tsc-frequency-*
# buckets per node from tsc-scalable=true. Before the fix, the scheduling
# labels' literal "true" value silently overwrote the correct cpu-timer
# value in the Python parser (always "consistent"), and the bash lookup's
# bare-key miss always reported "absent" -- both false negatives that would
# have hidden a genuine 0x101 live-migration risk on this real hardware.
run_case tsc-realworld-mismatch win2k22-good 0 2 0 4

# win2k22-good VM with a running VMI (guestOSInfo populated) exercises the
# VMI-present branches of Gate11 (PVC-backed disk -> advisory WARN) and
# Gate13 (QGA reporting -> OK), which the other scenarios (no VMI) skip.
run_case vmi-running win2k22-good 0 1 0 5

# R-03 / U-02: the live regression. evictionStrategy=LiveMigrate on a RUNNING
# VMI whose LiveMigratable condition is False (NoTSCFrequencyNotLiveMigratable
# -- HyperV Reenlightenment in the stock Windows templates plus absent TSC node
# labels). Gate 6 previously returned [ OK ] here on the strength of the spec
# field alone: measured live, 19 of 20 running Windows VMIs across two clusters
# had exactly this shape and were all cleared, while the shipped
# BSODRisk_EvictionBlocked alert was concurrently FIRING on nine of them.
# Expect Gate 6 WARN (+ the usual Gate 10 multiqueue WARN) and exit 0 -- it is a
# warning, not a hard failure, unless --strict is passed.
run_case livemigratable-false win2k22-good 0 2 0 5

# R-07 / U-03: Gate 19 must not report "N Windows preference(s) compliant" when
# the WORKER NODE LIST was unreadable. The arch-capabilities sub-check is gated
# on CACHED_CPU_VENDOR_AMD, derived from that list; an unreadable list left the
# counter at 0 -- indistinguishable from "no AMD nodes" -- so a fully-compliant
# verdict was emitted having never assessed the KCS-7125237 (0x5D) dimension at
# all. This fixture's preferences are compliant on every dimension that does NOT
# need the node list, so that verdict is the ONLY thing the fix changes;
# must-not-contain.txt pins that it can never reappear.
run_case nodes-unreadable-prefs-readable win2k22-good 0 2 0 8

# R-12 / U-11: Gates 17/19 must test enlightenment COMPLETENESS, not presence.
# This preference declares `preferredHyperv: {relaxed: {}}` -- non-null, so the
# old `== null` check called it compliant, while bsod_template_checks.py WARNed
# on the five missing required features. vpindex/synic/synictimer are the timer
# enlightenments tied to CLOCK_WATCHDOG_TIMEOUT (0x101) on live migration, so
# "has a hyperv block" was never the safety property worth asserting.
run_case preference-partial-hyperv win2k22-pref-test 1 1 1 3

# R-11 / U-10: Gate 7 must express KCS-7132519's COMPOUND condition.
# Migration-source annotations on the top-level VM (Forklift/VMware, the shape
# MTV actually produces) PLUS a WSL hint on the template. The old gate tested
# one boolean with no migration dimension at all, so it emitted a plain WARN
# here while the Python rule returned FAIL -- and --strict could not reconcile
# them, because promoting unconditionally then over-reported the STANDALONE
# nested case that Python calls WARN. Three branches now, matching Python in
# default mode; --strict remains strictly stricter, not divergent.
run_case wsl-migrated-compound win2k22-wsl-migrated 1 1 1 4

# R-13 / U-06: Gate 8 must derive the AMD family from a label KubeVirt actually
# emits. It read only `cpu-family.*node.kubevirt.io`, which KubeVirt has never
# emitted -- so CACHED_AMD_RISK could never be set and the entire microcode
# block, including the already-written oc-debug probe, was dead code on every
# stock cluster ([UNKN] on 100% of AMD nodes, both review clusters).
# host-model-cpu.node.kubevirt.io/<model> IS emitted; Zen mapping is
# Rome=17h, Milan/Genoa=19h, Turin=1Ah, and KCS-7132511 covers only Family 1Ah.
#
# amd-turin       reaches the probe block (previously unreachable) -- the WARN
#                 here is the BSOD_SKIP_MICROCODE_PROBE=1 branch this harness
#                 always sets, which only fires once the family is known.
# amd-genoa       correctly ruled OUT by family (Zen 4, Family 19h).
# amd-rome        correctly ruled OUT by family (Zen 2, Family 17h) -- Issue D1
#                 acceptance criteria named this codename explicitly; it is the
#                 model observed live on cluster-f5rfz and previously exercised
#                 the *rome|naples* case arm through zero dedicated fixtures.
# amd-milan       correctly ruled OUT by family (Zen 3, Family 19h) -- the model
#                 observed live on cluster-thdjk. Shares its case arm with
#                 amd-genoa but is fixtured under its own real-world name too.
# amd-unknown-model  FAIL-SAFE: an unrecognised codename must stay [UNKN] and
#                 must never be cleared -- a future EPYC part is exactly the
#                 case that must not be silently passed.
run_case amd-turin win2k22-good 0 4 0 4
run_case amd-genoa win2k22-good 0 3 0 4
run_case amd-rome win2k22-good 0 3 0 4
run_case amd-milan win2k22-good 0 3 0 4
run_case amd-unknown-model win2k22-good 0 3 0 5

# R-08 / U-04: --fail-on-unknown must be honoured on the --cluster-scope-only
# exit path too. That path returns from the middle of the script and never
# reaches the global enforcement at the bottom, so the flag parsed cleanly,
# appeared in --help, and silently did nothing. Not hypothetical:
# cnv-mtv-plan-gate.sh invokes exactly `$STRICT_FLAG --cluster-scope-only`, so
# an unattended migration gate asking to block on unassessed checks was not
# blocking on the cluster-scope half of its own audit.
#
# The pair is the assertion: identical UNKN count, exit differs ONLY by the flag.
run_case good win2k22-good 0 0 0 1 --cluster-scope-only
run_case good win2k22-good 0 0 1 1 --cluster-scope-only --fail-on-unknown

# phantom-nic: win2k22-good VM with guest evidence including a real
# PhantomNICConfig.csv AND PhantomDevices.csv (Get-PnpDevice CSV export
# format collect-windows-guest-info.ps1 actually writes -- see the
# 2026-08-13 Gate 16 fix below) with 2 genuine VMware-signature devices
# (VMware Accelerated AMD PCNet Adapter, vmxnet3) that are both Class=Net,
# so a real vmxnet3 residue would appear in both files simultaneously.
# Gate 16 FAIL-parity (KCS-7132519): vmxnet3 is high-risk
# (is_high_risk_vmware_device) so that half is [FAIL], not [WARN]. The
# generic phantom-NIC-config count (2) from PhantomNICConfig.csv stays
# [WARN] (KCS-263043). Gate10 WARNs as usual (multiqueue). Gate15 UNKN
# (no virtio_version.txt). host-model is the remaining WARN.
run_case phantom-nic win2k22-good 1 2 1 3

# phantom-nic-absent-ok: guest evidence dir exists and collected other real
# artifacts (virtio_version.txt, a valid 1.9.57 package version -> Gate15
# PASS) but has neither PhantomNICConfig.csv nor PhantomDevices.csv --
# reproducing 3 of 5 real guests in the 2026-08-13 live win-vms QGA
# collection, where collect-windows-guest-info.ps1 genuinely found zero
# phantom devices and correctly omitted both files rather than writing an
# empty CSV. Gate16 reports [ OK ] x2 (phantom NIC configs, VMware devices),
# NOT [UNKN] -- collection demonstrably ran; the file's absence IS the
# "checked, found none" signal, matching Python's check_phantom_nic_config's
# "not phantom_nic_configs -> PASS" semantics. The 1 WARN/2 UNKN below are
# unrelated pre-existing findings on this VM spec (cpu.model=host-model;
# OCP-version + multiqueue evidence gaps), confirming Gate16 itself
# contributes zero WARN/UNKN here -- see the fixture's full captured output.
run_case phantom-nic-absent-ok win2k22-good 0 1 0 2

# vmware-drv-active: same baseline as phantom-nic-absent-ok plus a real
# vmware_drv_list.csv with an active VMMemCtl row (the N8 collector shape;
# drv_list.csv is virtio-filtered and must NOT be used here). Gate 16 must
# [FAIL] on the active driver (KCS-7132519) and still [ OK ] the phantom-NIC
# half. Exit 1. Do not convert UNKNOWN to OK -- this fixture has a guest dir.
run_case vmware-drv-active win2k22-good 1 1 1 2

# vmware-phantom-lowrisk: PhantomDevices.csv with a VMware-signature device
# that is NOT high-risk (VMware Pointing Device -- in VMWARE_SIGNATURES but
# not is_high_risk_vmware_device). Gate 16 [WARN]s, zero [FAIL]. Proves the
# FAIL path is reserved for VMMemCtl/vmxnet/pvscsi/SVGA.
run_case vmware-phantom-lowrisk win2k22-good 0 2 0 2

# phantom-nic-nonvmware: PhantomNICConfig.csv present with 2 real-world

# phantom-nic-nonvmware: PhantomNICConfig.csv present with 2 real-world
# non-VMware phantom NICs (WAN Miniport (PPPOE)/(PPTP) -- reproducing win11's
# exact live 2026-08-13 collection byte-for-byte) but no PhantomDevices.csv,
# and no virtio_version.txt (Gate15 correctly UNKN here, unlike phantom-nic
# above which has real package-version evidence). Gate16 WARNs once (generic
# phantom-NIC-config count=2) and OKs once (no VMware-signature devices) --
# proving the two sub-checks are independent and the VMware-specific line
# does not silently inherit the generic count.
run_case phantom-nic-nonvmware win2k22-good 0 2 0 3

# virtio-version-bom: virtio_version.txt contains a real UTF-8 BOM
# (0xEF 0xBB 0xBF) prefix, byte-for-byte identical to what
# collect-windows-guest-info.ps1 actually wrote on a real win-vms guest
# 2026-08-13 (PowerShell 5.1's `Out-File -Encoding utf8` always prepends one;
# PS 5.1 has no `-Encoding utf8NoBOM`). Before the fix, `tr -d '[:space:]'`
# left the BOM in place, `int()`-equivalent parsing failed, and Gate 15
# reported [WARN] unparseable_version for a perfectly valid real version.
# Gate 15 must report [ OK ] PASS with the clean "1.9.57" value (no visible
# BOM bytes in the message), proving the sed strip runs before tr.
run_case virtio-version-bom win2k22-good 0 1 0 2

# --stop-code filter: only run gates relevant to 0x4E (Gate 8) -- should skip
# all per-VM gates and only get cluster-scope. On Intel/no-AMD nodes, Gate8
# OKs without warnings, so 0 WARN/FAIL (all per-VM gates skipped). Gate 20 is
# deliberately stop-code-agnostic and always runs regardless of filter (N11):
# on this fixture (no clusterversion.txt) it emits exactly one [UNKN] line.
run_case good          win2k22-good      0 0 0 1 --stop-code 0x4E

# N11: Gate 20's map entry ("*") must never disable the gate under
# --stop-code filtering, regardless of which code is requested -- it is
# stop-code-agnostic by design (reports alert *coverage*, not a specific
# BSOD risk). Pre-fix, GATE_STOP_CODES[20]="" read as "no codes match this
# gate" and gate_enabled() silently skipped it under ANY --stop-code.
n11_out=$(PATH="$MOCK_BIN_DIR:$PATH" \
      MOCK_OC_FIXTURE_DIR="$FIXTURES_DIR/good" \
      BSOD_SKIP_MICROCODE_PROBE=1 \
      BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
      BSOD_GUEST_EVIDENCE_DIR="$FIXTURES_DIR/good/no-such-guest-evidence" \
      "$AUDIT_SCRIPT" --stop-code 0x4E bsod-test win2k22-good 2>&1)
if echo "$n11_out" | grep -q 'Gate 20: \[SKIP\]'; then
  echo "FAIL: n11-gate20-stopcode -- Gate 20 was skipped under --stop-code 0x4E"
  FAIL_COUNT=$((FAIL_COUNT+1))
elif echo "$n11_out" | grep -q 'Gate 20: Prometheus alert coverage'; then
  echo "PASS: n11-gate20-stopcode (Gate 20 ran under --stop-code, not disabled by its always-on sentinel)"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: n11-gate20-stopcode -- Gate 20 header not found in output at all"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# N11 (JSON leak guard): the always-on sentinel ("*") must never leak into a
# finding's stop_code field via emit_finding()'s/set_gate()'s fallback chain.
n11_json=$(PATH="$MOCK_BIN_DIR:$PATH" \
      MOCK_OC_FIXTURE_DIR="$FIXTURES_DIR/good" \
      BSOD_SKIP_MICROCODE_PROBE=1 \
      BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
      BSOD_GUEST_EVIDENCE_DIR="$FIXTURES_DIR/good/no-such-guest-evidence" \
      "$AUDIT_SCRIPT" --json --stop-code 0x4E bsod-test win2k22-good 2>&1)
n11_star_leak=$(echo "$n11_json" | jq -e '[.cluster_scope.findings[] | select(.gate==20) | select(.stop_code=="*")] | length' 2>/dev/null || echo -1)
if [ "$n11_star_leak" = "0" ]; then
  echo "PASS: n11-gate20-stopcode-json (no Gate 20 finding leaks stop_code=\"*\")"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: n11-gate20-stopcode-json -- a Gate 20 finding leaked stop_code=\"*\" (got count=$n11_star_leak)"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# --- Gate 17: Template compliance (cluster-scope) ---
# Template fixture has 1 Windows template missing hyperv block -> Gate17 WARN.
# Per-VM: single-vCPU well-configured VM gets Gate15/16 WARNs. (Gate10 OKs
# because single vCPU = no multiqueue risk.)
run_case template-no-hyperv win2k22-tmpl-test 0 1 0 3

# --- Gate 19: Preference compliance (cluster-scope) ---
# Preference fixture has 1 Windows preference missing preferredHyperv -> Gate19 FAIL.
# Per-VM: single-vCPU well-configured VM gets Gate15/16 WARNs only.
run_case preference-no-hyperv win2k22-pref-test 1 1 1 3

# --- Gate 10: blockMultiQueue explicitly disabled (regression: false != absent) ---
# VM has 4 vCPUs + 2 virtio-blk disks (would normally trigger implicit multiqueue
# WARN) but explicitly sets blockMultiQueue: false. Gate10 must report OK (not
# WARN). Only Gate15 (no guest evidence) and Gate16 (phantom NIC unknown) warn.
run_case multiqueue-disabled win2k22-multiqueue-safe 0 1 0 3

# --- Instancetype resolution (regression: sparse spec handled gracefully) ---
# VM has instancetype/preference refs but empty inline domain. Without
# spec_expansion=false (no clusterversion -> stream unknown -> expansion=true),
# the per-VM gates see empty domain fields -> WARNs on Gate1 (no disks),
# OCP 4.21 stream (el9_6) has spec_expansion=false; VM domain is sparse but VMI
# has the fully expanded domain. Verifies that Gates 1/2/4/5 resolve from the
# VMI (pass) and only Gate10 (multiqueue), Gate15, Gate16 warn.
# Master remediation plan (Phase 4): this fixture's vm.json previously
# declared NO volumes at all (unrealistic -- even a real sparse-domain VM
# still has its own rootdisk PVC/DataVolume reference), which incidentally
# also meant Gate21 (virtio-win source attached) always WARNed and Gate11
# (storage latency) never fired at all (its PVC-detection field was always
# empty). Added a rootdisk PVC + virtio-win containerDisk volume to make
# this fixture realistic: Gate21 now PASSes (source attached) and Gate11
# now correctly UNKNs (PVC-backed disk present, cluster API can't measure
# latency) -- 3 UNKN total (Gate11, Gate15, Gate16).
run_case instancetype-resolution win2k22-instancetype 0 1 0 4

# --- R-9: Heterogeneous CPU node scenarios ---
# heterogeneous-cpu: Two Intel nodes with different CPU models (Skylake vs
# Cascade Lake). VM has unset cpu.model (host-model). No Gate4 WARN because
# the cluster is same-vendor (both Intel) -- intra-vendor heterogeneity is
# not detectable cluster-side. Gate10 (multiqueue), Gate11 (advisory storage),
# Gate15 (guest version), Gate16 (phantom NIC).
run_case heterogeneous-cpu win2022-hetcpu    0 0 0 5

# heterogeneous-vendor: One Intel + one AMD node. VM has unset cpu.model.
# Gate8 WARNs (AMD microcode probe skipped), Gate9 per-VM WARN
# (arch-capabilities not disabled), Gate10 (multiqueue), Gate11 (advisory
# storage), Gate12 WARN (TSC mismatch from different CPU frequencies),
# Gate15 (guest version), Gate16 (phantom NIC).
#
# v0.17.0 (F3): WARN count drops from 5 to 4 -- Gate9's cluster-scope "AMD
# present" line (a redundant pointer to the per-VM check listed above) is now
# info(), not warn(). Gate9 per-VM and every other WARN listed are unaffected.
run_case heterogeneous-vendor win2022-vendor-mix 0 3 0 5

# homogeneous-multi-node: Three identical Intel Cascade Lake nodes (control).
# VM has EXPLICIT cpu.model=Cascadelake-Server. Gate4 OKs (explicit model).
# Gate10 (multiqueue: 2 vCPUs + virtio-blk), Gate11 (advisory storage),
# Gate15 (guest version), Gate16 (phantom NIC).
run_case homogeneous-multi-node win2022-homogeneous 0 0 0 5

# T3 / Gate 20: alert-coverage gap. vms.json holds a 3-VM namespace where only
# win2k22-good carries vm.kubevirt.io/os. The other two are still Windows VMs
# by the detection contract -- winsql-01 via the name fallback, legacy-app-server
# via its hyperv feature block -- but neither would appear in
# kubevirt_vmi_info{os=~"windows|win.*"}, so BSODRisk_MemoryPressure and
# BSODRisk_EvictionBlocked can never fire for them. Gate20 WARNs 2/3.
# This fixture ships clusterversion.txt (4.21.0), so Gate20's second sub-check
# takes the OK branch (4.14+ exports node labels) instead of the UNKN branch the
# version-less fixtures above exercise -- both sides of that branch are pinned.
# Remaining findings: Gate10 multiqueue WARN, Gate15/Gate16 guest-evidence UNKNs.
run_case alert-coverage-gap win2k22-good 0 2 0 3

# N21: Gate 20's second sub-check (node-label export), <4.14 branch. Identical
# fixture data to alert-coverage-gap above (same 3-VM annotation gap), but
# clusterversion.txt is pinned at 4.13.0 instead of 4.21.0 -- this is below
# the kube-state-metrics nodes=[*] default (4.14+), so the sub-check that
# alert-coverage-gap proves takes the OK branch on here instead WARNs that
# BSODRisk_AMDNodeRequiresMicrocodeVerification and
# BSODRisk_HeterogeneousCPUMigration are silently blind by default. This was
# previously untested -- both branches of the OCP-version comparison are now
# pinned (see alert-coverage-gap's comment for the >=4.14 OK side).
# Expected WARNs (3 total): Gate20 annotation-gap sub-check (1 line covering
# 2/3 VMs) + Gate20 <4.14 node-label sub-check (new) + Gate10 multiqueue,
# same as alert-coverage-gap's breakdown plus the one new <4.14 WARN.
# Gate15/Gate16 guest-evidence UNKNs unchanged (2).
run_case alert-coverage-old-ocp win2k22-good 0 3 0 3

# M-10: kind-aware instancetype/preference resolution. The VM is stopped (no
# VMI) on a spec_expansion=false stream, so the referenced preference is the
# ONLY source for its effective domain. Both a namespaced VirtualMachinePreference
# and a cluster-scoped VirtualMachineClusterPreference named "windows.2k22"
# exist, and they differ: only the namespaced one (which the VM actually
# references) supplies preferredHyperv. Resolution therefore has an observable
# discriminator -- Gate5 OKs only if the NAMESPACED index was used. Before the
# fix, `kind` was ignored and the lookup always hit the cluster index, so this
# VM resolved against the wrong object and Gate5 WARNed on a VM whose real
# preference sets every enlightenment.
# Remaining: Gate1 (sparse spec, no boot disk to isolate) and Gate4 (cpu.model
# unset) WARN; Gate15/Gate16 guest-evidence UNKNs.
run_case namespaced-preference win2k22-nspref 0 2 0 2

# N13: bash instancetype-kind resolution. The VM is stopped (no VMI) and
# references a NAMESPACED VirtualMachineInstancetype (cpu.guest=4) by name
# "ns-large-mq" -- a CLUSTER-scoped instancetype with the SAME name but
# cpu.guest=1 also exists, so (like namespaced-preference above) the test has
# an observable discriminator: only the namespaced object's real vCPU count
# resolving correctly proves `kind` was honored, not just `name`. Before the
# fix, `vm_it_name` was extracted but never resolved at all, so the VM's
# sparse spec.domain.cpu was left empty and every downstream gate saw the
# default sockets=1/cores=1/threads=1 (1 total vCPU) -- Gate 14 never sees a
# Desktop socket-cap violation and Gate 10 never sees implicit multiqueue,
# regardless of the instancetype's real size. After the fix, KubeVirt's
# default cpu.preferredCPUTopology="sockets" projection (no preference is
# referenced here) puts all 4 vCPUs in sockets, so Gate 14 WARNs (sockets=4
# > the Windows 10/11 Desktop 2-socket cap) and Gate 10 WARNs (2 virtio-blk
# disks + 4 vCPUs => KubeVirt implicit multiqueue) -- two findings that were
# structurally impossible to reach before N13. Gate 4 (cpu.model unset) and
# Gate 5 (no hyperv block) WARN regardless of the fix (unrelated to
# instancetype resolution); Gate 15/16 UNKN (no guest evidence).
run_case namespaced-instancetype-mq win10-ns-instancetype-mq 0 3 0 3

# --- N2: UNKNOWN-only VM must not be classified/banner'd as "all checks
# passed". template-no-hyperv's per-VM fixture (win2k22-tmpl-test) has 0
# FAIL/WARN of its own (Gate17's WARN is cluster-scope) and exactly 2 UNKNOWN
# (Gate15/16, no guest evidence) -- verify the per-VM banner says UNASSESSED,
# not "all checks passed", and is not silently counted as PASS.
# NOTE (Issue H / Gate 4 fix): this fixture's cpu.model is pinned to an
# explicit "EPYC-Milan" rather than the "host-model" nearly every other
# fixture uses, specifically so it does NOT also pick up Gate 4's now-correct
# WARN (see the amd-* / good / etc. run_case comments below) -- that would
# break this test's "exactly 0 per-VM FAIL/WARN" premise for a reason
# unrelated to what N2 actually verifies.
out=$(PATH="$MOCK_BIN_DIR:$PATH" \
      MOCK_OC_FIXTURE_DIR="$FIXTURES_DIR/template-no-hyperv" \
      BSOD_SKIP_MICROCODE_PROBE=1 \
      BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
      BSOD_GUEST_EVIDENCE_DIR="$FIXTURES_DIR/template-no-hyperv/no-such-guest-evidence" \
      "$AUDIT_SCRIPT" bsod-test win2k22-tmpl-test 2>&1)
if echo "$out" | grep -q '── win2k22-tmpl-test: all checks passed ──'; then
  echo "FAIL: n2-unknown-banner -- UNKNOWN-only VM still reported as 'all checks passed'"
  FAIL_COUNT=$((FAIL_COUNT+1))
elif echo "$out" | grep -q '── win2k22-tmpl-test \[.*\]: 2 UNASSESSED'; then
  echo "PASS: n2-unknown-banner (UNKNOWN-only VM correctly reported as UNASSESSED, not PASS)"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: n2-unknown-banner -- expected an UNASSESSED banner line, got:"
  echo "$out" | grep '──'
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# H3 -- api-unavailable: EVERY `oc` call fails (expired token / netsplit).
# No check has any evidence, so none may report a pass; the harness asserts
# zero [ OK ] lines independently of the counts below. Before v0.16.0 this
# exact scenario returned exit 0 with six [ OK ] verdicts, because
# `oc get ... || echo '{"items":[]}'` made an API failure indistinguishable
# from an empty cluster. Gate 0 and every cluster-scope gate now report UNKN
# ("we could not look" -- N21/v0.16.0 #1 changed the unreadable single-VM
# fetch from flag()/FAIL to unknown()/UNKN, matching the contract's own
# stated philosophy that absence of evidence is not itself a finding).
# --fail-on-unknown is passed so a total API outage still fails closed for an
# unattended caller, exercising the same opt-in H2 promotion path.
run_case api-unavailable   win2k22-good      0 0 1 8 --fail-on-unknown

# H3 -- api-rbac-partial: the realistic case. A namespaced ServiceAccount can
# read VMs but not nodes/templates/cluster instancetypes/preferences. Per-VM
# checks that read only the VM's own spec still pass legitimately (7 [ OK ]);
# what must NOT appear is any conclusion drawn from the unreadable data --
# especially `arch-capabilities check passed (... amd_nodes=0)`, a KCS-7125237
# (0x5D) verdict that used to pass *because* the node list was unreadable.
# See must-not-contain.txt for the forbidden conclusions.
run_case api-rbac-partial win2k22-good 0 2 0 10

# H3 follow-up (v0.16.0 #1) -- api-namespace-scope-fail: distinct from both
# scenarios above. Cluster-scope reads succeed (nodes/templates/instancetypes/
# preferences all readable), but the PER-NAMESPACE `oc get vm`/`oc get vmi`
# calls fail for one of two namespaces discovered via --all-namespaces. Before
# this fix, `CACHED_VM_LIST_JSON=$(oc get vm -n $ns ... || echo '{"items":[]}')`
# made that failure indistinguishable from "this namespace genuinely has zero
# VMs" -- the namespace was silently skipped with no evidence of the gap. Now
# it surfaces as an explicit [UNKN] instead. must-not-contain.txt guards
# against the namespace being silently treated as legitimately empty.
run_case api-namespace-scope-fail "" 0 2 0 5 --all-namespaces

# H3 follow-up (v0.16.0 #1) -- vmi-list-unreadable-sparse-spec: the VM list
# succeeds but the VMI list alone is unreadable (distinct RBAC verb), on an
# OCP 4.19+ (sparse-spec) cluster where this VM's vCPU topology comes from an
# instancetype, not its own raw spec. Before this fix, an unreadable VMI list
# was indistinguishable from "VM is stopped" -- the code fell back to the
# cached instancetype and reported a confirmed vCPU count / socket count, even
# though a *running* VM's real (possibly different) VMI-reported topology was
# never actually checked. Gates 10/11/13/14 must report [UNKN], not a
# resolved topology or a deferred-silently QGA/storage check. See
# must-not-contain.txt for the specific false-OK conclusions this proves are
# no longer reachable.
run_case vmi-list-unreadable-sparse-spec win10-vmi-unreadable 0 2 0 6

# JSON output mode: verify parseable JSON is emitted
run_case_json good     win2k22-good      0  LOW  0 1

# F-03: the at-stream-max WARN must be emitted under GATE 22, and the VM must
# stay LOW. Before v0.27.0 this scored 4.50 in the `driver` domain --
# identically on every VM of a capped stream, for a condition only an OCP
# upgrade can clear -- consuming 90% of the LOW->MEDIUM budget fleet-wide.
run_case_json stream-capped-el9-4 win2k22-good 0 LOW 0 2
run_case_json bad      win2k22-bad       1  HIGH 1 4

# R-27 Phase 2 (Issue K) end-to-end check: a fully-unreachable VM produces NO
# vm_record at all, not a vm_record with assessed_count:0. Empirically
# verified while implementing this phase -- the api-unavailable scenario's
# total outage (see the H3 comment above run_case_json) fails `oc get vm`
# itself, so the VM is never discovered and the per-VM loop never runs for
# it; .vms is [] and .summary.total_vms is 0. This is the important
# real-world case to pin down: scripts/cnv-bsod-fleet-exporter.sh's
# assessed_count==0 -> tier="UNKNOWN" override (write_metrics() in
# scripts/cnv-bsod-fleet-exporter.sh) only ever sees VMs that DO appear in
# .vms[] -- it must never be asked to invent a placeholder record for a VM
# missing from the audit's own output. That per-record override logic (given
# a record that DOES exist with assessed_count:0, a shape this fixture set
# has no organic example of) is exercised at the unit level instead, in
# tests/test_bash_fleet_exporter.sh's synthetic-stub scenarios, where it can
# be constructed directly.
run_case_json_empty_vms() {
  local scenario="api-unavailable" vm_name="win2k22-good"
  local fixture_dir="$FIXTURES_DIR/$scenario"
  local fail_pattern; fail_pattern=$(head -1 "$fixture_dir/oc-fail-pattern.txt")
  local out
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        MOCK_OC_FAIL_PATTERN="$fail_pattern" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        BSOD_GUEST_EVIDENCE_DIR="$fixture_dir/no-such-guest-evidence" \
        "$AUDIT_SCRIPT" --json --fail-on-unknown "$NS" "$vm_name" 2>&1)
  local label="$scenario (--json --fail-on-unknown, .vms emptiness)"
  local ok=1
  if ! echo "$out" | jq -e '.vms == []' >/dev/null 2>&1; then
    echo "FAIL: $label -- expected .vms == [] for a totally unreachable VM, got: $(echo "$out" | jq -c '.vms' 2>/dev/null)"
    ok=0
  fi
  if ! echo "$out" | jq -e '.summary.total_vms == 0' >/dev/null 2>&1; then
    echo "FAIL: $label -- expected .summary.total_vms == 0"
    ok=0
  fi
  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_case_json_empty_vms

# --- cnv-mtv-plan-gate.sh --json tests ---

PLAN_GATE_SCRIPT="$REPO_ROOT/scripts/cnv-mtv-plan-gate.sh"

run_plan_gate_json() {
  local label="$1" plan_json="$2" mock_audit="$3" expect_verdict="$4" expect_exit="$5"

  local json_file
  json_file="$(mktemp)"

  local out actual_exit
  out=$(MTV_PLAN_JSON="$plan_json" \
        BSOD_CHECK_CMD="$mock_audit" \
        "$PLAN_GATE_SCRIPT" test-plan test-ns --json "$json_file" 2>&1)
  actual_exit=$?

  local ok=1
  if [ "$actual_exit" -ne "$expect_exit" ]; then
    echo "FAIL: plan-gate-json/$label -- expected exit=$expect_exit, got $actual_exit"
    ok=0
  fi
  if [ ! -s "$json_file" ]; then
    echo "FAIL: plan-gate-json/$label -- JSON file is empty or missing"
    ok=0
  elif ! jq . "$json_file" >/dev/null 2>&1; then
    echo "FAIL: plan-gate-json/$label -- JSON file is not valid JSON"
    ok=0
  else
    local got_verdict
    got_verdict=$(jq -r '.verdict' "$json_file")
    if [ "$got_verdict" != "$expect_verdict" ]; then
      echo "FAIL: plan-gate-json/$label -- expected verdict=$expect_verdict, got $got_verdict"
      ok=0
    fi
    if ! jq -e '.vms | length > 0' "$json_file" >/dev/null 2>&1; then
      echo "FAIL: plan-gate-json/$label -- .vms array empty"
      ok=0
    fi
    if ! jq -e '.totals' "$json_file" >/dev/null 2>&1; then
      echo "FAIL: plan-gate-json/$label -- missing .totals"
      ok=0
    fi
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: plan-gate-json/$label (verdict=$expect_verdict exit=$actual_exit)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- plan-gate-json/$label output ----"
    echo "$out" | tail -5
    [ -s "$json_file" ] && jq . "$json_file" 2>/dev/null | head -10
    echo "---- end ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
  rm -f "$json_file"
}

# Create a minimal Plan JSON fixture (two VMs)
PLAN_GATE_FIXTURE_DIR="$(mktemp -d)"
cat > "$PLAN_GATE_FIXTURE_DIR/plan-pass.json" <<'PLAN_EOF'
{
  "apiVersion": "forklift.konveyor.io/v1beta1",
  "kind": "Plan",
  "metadata": {"name": "test-plan", "namespace": "test-ns"},
  "spec": {
    "targetNamespace": "target-ns",
    "warm": false,
    "vms": [
      {"name": "win2k22-a", "id": "vm-001"},
      {"name": "win2k22-b", "id": "vm-002"}
    ]
  }
}
PLAN_EOF

# Mock audit that always passes (no FAIL/WARN lines)
cat > "$PLAN_GATE_FIXTURE_DIR/mock-audit-pass.sh" <<'MOCK_EOF'
#!/usr/bin/env bash
echo "[ OK ] All gates clear"
exit 0
MOCK_EOF
chmod +x "$PLAN_GATE_FIXTURE_DIR/mock-audit-pass.sh"

# Mock audit that always FAILs
cat > "$PLAN_GATE_FIXTURE_DIR/mock-audit-fail.sh" <<'MOCK_EOF'
#!/usr/bin/env bash
echo "[FAIL] Gate 1: Non-virtio boot disk"
exit 1
MOCK_EOF
chmod +x "$PLAN_GATE_FIXTURE_DIR/mock-audit-fail.sh"

run_plan_gate_json "all-pass" \
  "$PLAN_GATE_FIXTURE_DIR/plan-pass.json" \
  "$PLAN_GATE_FIXTURE_DIR/mock-audit-pass.sh" \
  "PASS" 0

run_plan_gate_json "all-fail" \
  "$PLAN_GATE_FIXTURE_DIR/plan-pass.json" \
  "$PLAN_GATE_FIXTURE_DIR/mock-audit-fail.sh" \
  "FAIL" 1

rm -rf "$PLAN_GATE_FIXTURE_DIR"

# --- Issue I: Gate 20 per-VM finding, distinct from the cluster-scope list ---
# Gemini's review flagged that a VM missing vm.kubevirt.io/os only ever showed
# up in Gate 20's cluster-scope aggregate WARN (up to ten names + "... and N
# more"), so the VM's OWN verdict line stayed clean -- an operator scanning
# per-VM output alone would never see the gap. Asserts all four acceptance
# criteria at once: (1) a per-VM finding exists, distinct from the
# cluster-scope list; (2) --suggest-annotate's command is reachable from that
# per-VM finding, not only the cluster-scope prologue; (4) the cluster-scope
# summary is unchanged/still present. (3) domain weighting is asserted
# separately below.
run_gate20_per_vm_case() {
  local scenario="legacy-client-name-fallback"
  local fixture_dir="$FIXTURES_DIR/$scenario"
  local label="$scenario (Gate 20 per-VM finding)"

  local out
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        "$AUDIT_SCRIPT" --suggest-annotate "$NS" winxp-legacy 2>&1)

  local ok=1
  local vm_banner_line
  vm_banner_line=$(echo "$out" | grep -n '^############# VM: bsod-test/winxp-legacy #############$' | head -1 | cut -d: -f1)
  if [ -z "$vm_banner_line" ]; then
    echo "FAIL: $label -- VM banner not found in output"
    ok=0
  fi

  # Criterion 1: a per-VM finding, not only cluster-scope list membership.
  # Must appear on/after the VM's own banner line, worded for a single VM
  # ("for this VM"/"for it"), not the cluster-scope aggregate's "N of M"
  # phrasing.
  local finding_line
  finding_line=$(echo "$out" | grep -n 'INVISIBLE to annotation-dependent alerts.*for this VM' | tail -1 | cut -d: -f1)
  if [ -z "$finding_line" ] || [ -n "$vm_banner_line" ] && [ "$finding_line" -lt "$vm_banner_line" ]; then
    echo "FAIL: $label -- no per-VM alert-blindness finding found on/after the VM's own banner"
    ok=0
  fi

  # Criterion 2: --suggest-annotate's command reachable from the per-VM
  # finding -- assert an oc patch line appears AFTER the per-VM finding line,
  # not only earlier in the cluster-scope prologue.
  local per_vm_patch_line
  per_vm_patch_line=$(echo "$out" | grep -n 'oc patch vm winxp-legacy' | tail -1 | cut -d: -f1)
  if [ -z "$per_vm_patch_line" ] || [ -n "$finding_line" ] && [ "$per_vm_patch_line" -lt "$finding_line" ]; then
    echo "FAIL: $label -- --suggest-annotate command not reachable from the per-VM finding"
    ok=0
  fi

  # Criterion 4: cluster-scope aggregate summary is retained (still fires
  # BEFORE the VM banner, in its original "N/M ... are INVISIBLE" phrasing).
  local cluster_scope_line
  cluster_scope_line=$(echo "$out" | grep -n '[0-9]*/[0-9]* Windows VM(s) are INVISIBLE to annotation-dependent alerts' | head -1 | cut -d: -f1)
  if [ -z "$cluster_scope_line" ] || [ -n "$vm_banner_line" ] && [ "$cluster_scope_line" -gt "$vm_banner_line" ]; then
    echo "FAIL: $label -- cluster-scope aggregate summary missing or not retained ahead of the per-VM loop"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out"
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_gate20_per_vm_case

# --- F11 (v0.17.0): Gate 20 --suggest-annotate dry-run mode ------------------
# Exercises all three suggestion sources against the alert-coverage-gap
# fixture's real VMs (winsql-01: matched only via the name-fallback regex,
# no os/template label at all; legacy-app-server: matched only via a
# hyperv feature block, likewise no identifying label) -- both must fall
# back to the flagged generic "windows" suggestion, never a confident one
# fabricated from nothing. Also guards the '|'-delimited field-parsing fix:
# an earlier @tsv-based implementation silently collapsed the empty
# vm.kubevirt.io/os-label field into the next column (bash `read` treats
# consecutive tab/IFS-whitespace delimiters as one, even under a custom
# IFS=$'\t'), which misattributed every fallback suggestion's stated source.
run_suggest_annotate_case() {
  local scenario="alert-coverage-gap"
  local fixture_dir="$FIXTURES_DIR/$scenario"
  local label="$scenario (--suggest-annotate)"

  local out
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        "$AUDIT_SCRIPT" --cluster-scope-only --suggest-annotate "$NS" 2>&1)

  local ok=1
  # Must print a real, syntactically complete oc patch command per blind
  # VM -- never merely a description of what one would look like. N24
  # (v0.17.0, F11 live-cluster validation on cluster-f5rfz): must be `oc
  # patch --type=merge` against spec.template.metadata.annotations, NOT
  # `oc annotate vm` -- the latter only patches the VM's own top-level
  # metadata.annotations (a different field from what Gate 20 actually
  # checks) and was proven live to leave the VM still uncovered.
  if ! echo "$out" | grep -qF 'oc patch vm winsql-01 -n bsod-test --type=merge -p '"'"'{"spec":{"template":{"metadata":{"annotations":{"vm.kubevirt.io/os":"windows"}}}}}'"'"; then
    echo "FAIL: $label -- missing expected patch command for winsql-01 (name-fallback-only match)"
    ok=0
  fi
  if ! echo "$out" | grep -qF 'oc patch vm legacy-app-server -n bsod-test --type=merge -p '"'"'{"spec":{"template":{"metadata":{"annotations":{"vm.kubevirt.io/os":"windows"}}}}}'"'"; then
    echo "FAIL: $label -- missing expected patch command for legacy-app-server (hyperv-only match)"
    ok=0
  fi
  # Both VMs here have no vm.kubevirt.io/os or vm.kubevirt.io/template label
  # to derive a confident suggestion from, so both MUST carry the fallback
  # flag -- asserting this is what the @tsv delimiter bug broke (it instead
  # printed the *next* field's value labeled as "from existing ... label").
  local fallback_count
  fallback_count=$(echo "$out" | grep -c 'GENERIC FALLBACK -- VERIFY')
  if [ "$fallback_count" -ne 2 ]; then
    echo "FAIL: $label -- expected 2 GENERIC FALLBACK-flagged suggestions, got $fallback_count"
    ok=0
  fi
  # win2k22-good already carries a matching annotation (not blind) and must
  # never get a suggestion of its own.
  if echo "$out" | grep -q 'oc patch vm win2k22-good'; then
    echo "FAIL: $label -- suggested annotating win2k22-good, which is already covered"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out"
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_suggest_annotate_case

# --- ARG_MAX regression guard (found live against cluster-thdjk, 2026-08-05,
# deploying Issue K's exporter as a real in-cluster Pod for the first time)
# -----------------------------------------------------------------------
# JSON_MODE=doc's final assembly used to pass the ENTIRE per-VM findings
# blob to `jq` via `--argjson vms "$_vms_json"` -- a shell ARGUMENT, not a
# file read. Linux's execve(2) caps any SINGLE argv/envp string at
# MAX_ARG_STRLEN (131072 bytes, 32 pages on every architecture that matters
# here) independently of the much larger total ARG_MAX budget -- so this
# broke as soon as one real fleet's accumulated findings text crossed that
# per-argument ceiling, with NO dependence on how many environment variables
# happened to be present. A 68-VM real fleet hit exactly this: `jq: Argument
# list too long`, jq exited non-zero, `--json`'s command substitution
# produced an empty string, and scripts/cnv-bsod-fleet-exporter.sh (the only
# consumer of this exact code path) correctly treated that as a hard
# collection failure -- silent data loss on a live audit run, not a
# cosmetic bug.
#
# Reproduced here deterministically, independent of the CI runner's own
# environment: a single argv string over the 131072-byte kernel ceiling
# fails identically regardless of ambient env-var count (verified directly
# against `true <150000-byte-arg>` while diagnosing this, no padding
# trick needed). No large fixture file is checked in for this -- the VMs are
# generated at test-run time from the existing alert-coverage-gap fixture's
# real "win2k22-good" VM (cpu.model: host-model triggers one WARN finding
# per copy), cloned enough times that the resulting per-VM findings JSON
# clears the threshold with a safe margin, confirmed empirically while
# writing this test (120 clones -> ~190KB, comfortably over 131072).
run_argmax_guard_case() {
  local label="argmax-guard (--json, 120-VM namespace, single-arg > MAX_ARG_STRLEN)"
  local vm_template="$FIXTURES_DIR/alert-coverage-gap/vm.json"
  if [ ! -f "$vm_template" ]; then
    echo "FAIL: $label -- missing template $vm_template"
    FAIL_COUNT=$((FAIL_COUNT+1))
    return
  fi

  local fixture_dir
  fixture_dir="$(mktemp -d)"
  # 120 clones of a real "good" VM in one namespace -- same template
  # alert-coverage-gap already uses, just replicated with unique names so
  # the per-VM findings blob (not the fixture file itself) is what grows.
  jq -n --slurpfile base "$vm_template" '
    { apiVersion: "v1", kind: "List",
      items: [range(120) as $i | $base[0]
        | .metadata.name = "argmax-vm-\($i)"
        | .metadata.namespace = "bsod-test"] }
  ' > "$fixture_dir/vms.json"
  if [ -f "$FIXTURES_DIR/alert-coverage-gap/clusterversion.txt" ]; then
    cp "$FIXTURES_DIR/alert-coverage-gap/clusterversion.txt" "$fixture_dir/"
  fi

  local out actual_exit
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        "$AUDIT_SCRIPT" --json "$NS" 2>&1)
  actual_exit=$?
  rm -rf "$fixture_dir"

  local ok=1
  # exit is 0 or 1 (FAIL findings present) -- both are legitimate outcomes.
  # exit 2 is the script's own "jq/oc missing or usage error" code and would
  # indicate something else entirely broke.
  if [ "$actual_exit" -ne 0 ] && [ "$actual_exit" -ne 1 ]; then
    echo "FAIL: $label -- expected exit 0 or 1, got $actual_exit"
    ok=0
  fi
  if grep -qi 'argument list too long' <<<"$out"; then
    echo "FAIL: $label -- regressed: 'Argument list too long' reappeared"
    ok=0
  fi
  if ! jq -e '.summary' <<<"$out" >/dev/null 2>&1; then
    echo "FAIL: $label -- output is not valid JSON with a .summary (this is exactly the failure mode: jq's own E2BIG makes the command substitution produce nothing)"
    ok=0
  fi
  local actual_total_vms
  actual_total_vms=$(jq -r '.summary.total_vms // "MISSING"' <<<"$out" 2>/dev/null)
  if [ "$actual_total_vms" != "120" ]; then
    echo "FAIL: $label -- expected .summary.total_vms == 120, got $actual_total_vms"
    ok=0
  fi
  local actual_vms_len
  actual_vms_len=$(jq -r '.vms | length' <<<"$out" 2>/dev/null || echo "MISSING")
  if [ "$actual_vms_len" != "120" ]; then
    echo "FAIL: $label -- expected .vms to have 120 entries (one per VM), got $actual_vms_len"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (exit=$actual_exit, total_vms=$actual_total_vms, valid JSON)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output (first 2000 chars): $label ----"
    echo "$out" | head -c 2000
    echo
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_argmax_guard_case

# --- F-07: the cluster-scope VM list must be acquired through _oc_fetch ------
#
# Both halves of this regression were live simultaneously: the fetch discarded
# its `oc` error (so the ACQUISITION ERRORS banner never printed for it) AND it
# had no retry (so a 429 became a permanent UNKNOWN, which --fail-on-unknown
# turns into a blocked migration wave).
#
# These assert BEHAVIOUR, not the call site: they fail against the pre-fix tree
# and pass after, without caring how the fetch is spelled.
run_cluster_scope_fetch_acquisition_case() {
  local label="cluster-scope VM fetch (F-07: error surfaced in ACQUISITION ERRORS)"
  local fixture_dir="$FIXTURES_DIR/good"
  local out
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        MOCK_OC_FAIL_PATTERN="get vm -n $NS -o json" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        "$AUDIT_SCRIPT" "$NS" win2k22-good 2>&1)

  local ok=1
  # The banner must fire at all -- pre-fix it did not, because nothing had
  # appended to ACQUISITION_ERRORS for this fetch.
  if ! grep -q 'ACQUISITION ERRORS' <<<"$out"; then
    echo "FAIL: $label -- no ACQUISITION ERRORS banner; the operator sees [UNKN] with no cause"
    ok=0
  fi
  # ...and it must name THIS fetch, carrying the underlying oc error text.
  if ! grep -qE 'VMs in namespace .*cluster-scope.*Unauthorized' <<<"$out"; then
    echo "FAIL: $label -- banner does not name the cluster-scope VM fetch with its oc error"
    ok=0
  fi
  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_cluster_scope_fetch_acquisition_case

run_cluster_scope_fetch_retry_case() {
  local label="cluster-scope VM fetch (F-07: transient 429 retried, not fatal)"
  local fixture_dir="$FIXTURES_DIR/good"
  local counter; counter="$(mktemp)"
  rm -f "$counter"
  local out
  # Fail exactly once, with a message _oc_fetch must classify as TRANSIENT
  # (a permanent authz error must still short-circuit -- that is R-24's
  # deliberate asymmetry, covered by the api-* scenarios above).
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        MOCK_OC_FAIL_PATTERN="get vm -n $NS -o json" \
        MOCK_OC_FAIL_MESSAGE='error: the server has received too many requests and has asked us to try again later (429)' \
        MOCK_OC_FAIL_TIMES=1 \
        MOCK_OC_FAIL_COUNTER="$counter" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        "$AUDIT_SCRIPT" "$NS" win2k22-good 2>&1)
  local failed_times; failed_times=$(cat "$counter" 2>/dev/null || echo 0)
  rm -f "$counter"

  local ok=1
  if [ "$failed_times" != "1" ]; then
    echo "FAIL: $label -- harness did not inject exactly one failure (got $failed_times)"
    ok=0
  fi
  if ! grep -q 'recovered VMs in namespace' <<<"$out"; then
    echo "FAIL: $label -- fetch was not retried; a 429 still becomes a permanent UNKNOWN"
    ok=0
  fi
  # Recovery means the data really arrived: no acquisition error should remain.
  if grep -q 'ACQUISITION ERRORS' <<<"$out"; then
    echo "FAIL: $label -- retry reported recovery but an acquisition error was still recorded"
    ok=0
  fi
  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_cluster_scope_fetch_retry_case

run_permanent_misconfig_no_retry_case() {
  local label="F-11: local kubeconfig misconfiguration is not retried"
  local fixture_dir="$FIXTURES_DIR/good"
  local counter; counter="$(mktemp)"; rm -f "$counter"
  local out
  # `oc`'s real message when the kubeconfig carries no usable credentials. No
  # retry can fix it, so the budget must not be spent: measured live at 38s
  # vs 1s across one audit before this was classified as permanent.
  # MOCK_OC_FAIL_TIMES=1 means a retry WOULD have succeeded -- so if the fetch
  # is retried, the attempt counter climbs past 1 and this fails.
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        MOCK_OC_FAIL_PATTERN="get vm -n $NS -o json" \
        MOCK_OC_FAIL_MESSAGE='error: Missing or incomplete configuration info.  Please point to an existing, complete config file:' \
        MOCK_OC_FAIL_TIMES=1 \
        MOCK_OC_FAIL_COUNTER="$counter" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        "$AUDIT_SCRIPT" "$NS" win2k22-good 2>&1)
  local attempts; attempts=$(cat "$counter" 2>/dev/null || echo 0)
  rm -f "$counter"

  local ok=1
  if [ "$attempts" != "1" ]; then
    echo "FAIL: $label -- fetch attempted $attempts time(s); a permanent local misconfiguration must be attempted once"
    ok=0
  fi
  if grep -q 'recovered VMs in namespace' <<<"$out"; then
    echo "FAIL: $label -- reported recovery, so the permanent error was retried"
    ok=0
  fi
  # It must still be REPORTED -- classifying it as permanent is about not
  # retrying, never about staying quiet.
  if ! grep -q 'ACQUISITION ERRORS' <<<"$out"; then
    echo "FAIL: $label -- permanent error was not surfaced in the banner"
    ok=0
  fi
  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"; PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_permanent_misconfig_no_retry_case

# --- F-06: BSOD_CLUSTER_CACHE_DIR is a public contract and must be safe ------
#
# The shipped caller (cnv-mtv-plan-gate.sh) uses mktemp + trap, so it was
# always safe. These pin the behaviour for the OTHER callers the variable is
# advertised to -- an operator's own wave loop pointing it at a persistent
# directory, which is the obvious reading of the CHANGELOG's "lets a fleet
# caller warm those fetches once".
run_cache_identity_cases() {
  local fixture_dir="$FIXTURES_DIR/good"
  local dir; dir="$(mktemp -d)"

  _cache_run() {
    PATH="$MOCK_BIN_DIR:$PATH" \
    MOCK_OC_FIXTURE_DIR="$fixture_dir" \
    BSOD_CLUSTER_CACHE_DIR="$dir" \
    BSOD_SKIP_MICROCODE_PROBE=1 \
    BSOD_SKIP_PROM_QUERY=1 \
    BSOD_OC_RETRIES=0 \
    "$AUDIT_SCRIPT" --all-namespaces 2>&1
  }
  _assert() {
    local label="$1" cond="$2"
    if [ "$cond" = "1" ]; then
      echo "PASS: $label"; PASS_COUNT=$((PASS_COUNT+1))
    else
      echo "FAIL: $label"; FAIL_COUNT=$((FAIL_COUNT+1))
    fi
  }

  # Warm the cache, then confirm a second run reuses it rather than discarding.
  _cache_run >/dev/null 2>&1
  local stamp="$dir/.bsod-cache-identity"
  local n
  n=$(_cache_run | grep -c 'cache discarded' || true)
  _assert "cache identity (same cluster, fresh -> reused)" "$([ "$n" -eq 0 ] && echo 1 || echo 0)"

  # A context switch to a different cluster must invalidate: every cached
  # answer then describes the WRONG fleet, not merely an older one.
  printf 'server=https://other-cluster.example:6443\n%s\n' "$(date +%s)" > "$stamp"
  local discard_out discard_err
  discard_err="$(mktemp)"
  discard_out=$(_cache_run 2>"$discard_err")
  n=$(printf '%s' "$discard_out" | grep -c 'different cluster' || true)
  _assert "cache identity (different cluster -> discarded)" "$([ "$n" -ge 1 ] && echo 1 || echo 0)"

  # LIVE-FOUND REGRESSION: asserting only that the NOTICE appears is not
  # enough. _cache_identity_ok was originally called from _oc_cache_path,
  # which runs as `$(...)` -- so the notice was captured INTO the cache path,
  # giving a two-line value and a broken redirect on the next write. The
  # audit still printed the message and still produced a report, so a
  # message-only assertion passed while the cache was corrupt. Only a real
  # cluster exposed it (under the mock, `oc whoami --show-server` always
  # returns the same value, so a cold cache never disagrees with a warm one
  # in the same process). Assert the CONSEQUENCES instead: no shell errors,
  # and the cache is actually rebuilt.
  _assert "cache discard emits no shell error (notice must not pollute a path)" \
    "$(grep -qE 'line [0-9]+:' "$discard_err" && echo 0 || echo 1)"
  local rebuilt=("$dir"/CACHED_NODES_JSON.*.json)
  _assert "cache discard repopulates rather than leaving it empty" \
    "$([ -f "${rebuilt[0]}" ] && echo 1 || echo 0)"
  rm -f "$discard_err"

  # Same cluster but beyond the TTL: bounds the rebuilt-cluster case that a
  # server URL alone cannot detect.
  local server_line; server_line=$(head -1 "$stamp")
  printf '%s\n%s\n' "$server_line" "$(( $(date +%s) - 100000 ))" > "$stamp"
  n=$(_cache_run | grep -c 'older than' || true)
  _assert "cache identity (stale beyond TTL -> discarded)" "$([ "$n" -ge 1 ] && echo 1 || echo 0)"

  # SAFETY: purging must remove only files this script owns. A caller may
  # point the variable at a directory holding other data, and deleting that
  # would be far worse than serving a stale cache.
  echo "PRECIOUS" > "$dir/user-data.txt"
  printf 'server=https://yet-another.example:6443\n%s\n' "$(date +%s)" > "$stamp"
  _cache_run >/dev/null 2>&1
  _assert "cache purge leaves non-cache files untouched" \
    "$([ -f "$dir/user-data.txt" ] && [ "$(cat "$dir/user-data.txt")" = "PRECIOUS" ] && echo 1 || echo 0)"

  # A changed QUERY must not be answered from the old query's file. Simulated
  # by renaming a cache entry onto a key that no current query hashes to: the
  # audit must ignore it and refetch rather than serve it.
  rm -f "$dir"/*.json
  _cache_run >/dev/null 2>&1
  local nodes_files=("$dir"/CACHED_NODES_JSON.*.json)
  if [ -f "${nodes_files[0]}" ]; then
    echo '{"items":[{"metadata":{"name":"POISONED"}}]}' > "$dir/CACHED_NODES_JSON.000000.json"
    _assert "cache key covers the oc query (stray key not served)" \
      "$(_cache_run | grep -qi 'POISONED' && echo 0 || echo 1)"
  else
    echo "FAIL: cache key covers the oc query -- no CACHED_NODES_JSON entry was written"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi

  rm -rf "$dir"
  unset -f _cache_run _assert
}
run_cache_identity_cases

# --- F-03: per-VM lookups must stay O(1) ------------------------------------
#
# The index was built once but every per-VM read piped the WHOLE index through
# a fresh jq, so the intended O(1) lookup was O(N) -- four times per VM, i.e.
# O(N^2) overall on the migration-blocking path.
#
# A wall-clock assertion would be flaky in CI and, worse, non-discriminating:
# the quadratic term is partly masked by a large linear constant, so a
# time(2N)/time(N) ratio does not cleanly separate the two shapes at testable
# fleet sizes. These pin the STRUCTURE that makes it O(1), plus the correctness
# edge cases the file-backed index introduces.
run_index_structure_case() {
  local label="F-03: per-VM lookups do not re-parse a whole-namespace blob"
  local ok=1

  # A regression would have to reintroduce a variable holding the entire
  # index and pipe it per VM. Both halves of that shape are rejected.
  if grep -qE '^\s*CACHED_VM_INDEX=|^\s*CACHED_VMI_INDEX=' "$AUDIT_SCRIPT"; then
    echo "FAIL: $label -- a whole-document index variable was reintroduced"
    ok=0
  fi
  # shellcheck disable=SC2016  # a literal grep pattern, not an expansion
  if grep -qE 'echo "\$CACHED_(VM|VMI)_INDEX"' "$AUDIT_SCRIPT"; then
    echo "FAIL: $label -- a per-VM lookup pipes the full index through jq again"
    ok=0
  fi
  # And the O(1) path must actually be the one in use.
  # shellcheck disable=SC2016  # a literal grep pattern, not an expansion
  if ! grep -q '_index_get "\$CACHED_VM_INDEX_DIR"' "$AUDIT_SCRIPT"; then
    echo "FAIL: $label -- VM spec lookup no longer goes through _index_get"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"; PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_index_structure_case

run_index_correctness_case() {
  local label="F-03: file-backed index round-trips awkward VM objects"
  local fixture_dir; fixture_dir="$(mktemp -d)"

  # Names carrying dots (legal DNS-1123 subdomains, and real in the field for
  # FQDN-style VM names) become part of a filename, and a spec carrying tabs,
  # quotes and newlines is what the name<TAB>json split has to survive. JSON
  # escapes all three inside strings, which is why the split is lossless --
  # this proves it rather than asserting it.
  jq -n --slurpfile base "$FIXTURES_DIR/alert-coverage-gap/vm.json" '
    { apiVersion: "v1", kind: "List",
      items: [ $base[0]
                 | .metadata.name = "win.dotted.name"
                 | .metadata.namespace = "bsod-test"
                 | .metadata.annotations["bsod.test/awkward"] = "tab\there quote\"here newline\nhere"
             ] }
  ' > "$fixture_dir/vms.json"
  [ -f "$FIXTURES_DIR/alert-coverage-gap/clusterversion.txt" ] && \
    cp "$FIXTURES_DIR/alert-coverage-gap/clusterversion.txt" "$fixture_dir/"

  local out
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        MOCK_OC_FIXTURE_DIR="$fixture_dir" \
        BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_SKIP_PROM_QUERY=1 \
        BSOD_OC_RETRIES=0 \
        "$AUDIT_SCRIPT" --json "$NS" 2>&1)
  rm -rf "$fixture_dir"

  local ok=1
  # The failure mode if the index breaks is "cannot read VM" -- the VM is
  # found by name in the list, then its object cannot be retrieved.
  if grep -q 'cannot read VM' <<<"$out"; then
    echo "FAIL: $label -- index lookup failed for a dotted name / awkward spec"
    ok=0
  fi
  if ! jq -e '.summary.total_vms == 1' <<<"$out" >/dev/null 2>&1; then
    echo "FAIL: $label -- expected 1 VM audited, got: $(jq -c '.summary.total_vms' <<<"$out" 2>/dev/null)"
    ok=0
  fi
  if ! jq -e '[.vms[].name] | index("win.dotted.name")' <<<"$out" >/dev/null 2>&1; then
    echo "FAIL: $label -- the dotted-name VM is missing from .vms[]"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label"; PASS_COUNT=$((PASS_COUNT+1))
  else
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_index_correctness_case

echo
echo "=============================================="
echo " test_bash_gates.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
