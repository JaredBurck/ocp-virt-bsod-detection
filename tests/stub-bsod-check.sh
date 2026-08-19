#!/usr/bin/env bash
#
# stub-bsod-check.sh
# -----------------------------------------------------------------------------
# Minimal stand-in for scripts/cnv-win-bsod-audit.sh used only by
# tests/test_fleet_readiness.sh (via BSOD_CHECK_CMD) to drive
# cnv-mtv-plan-gate.sh / cnv-mtv-fleet-readiness.sh through canned
# cluster-scope and per-VM outcomes without needing a live cluster or the
# real audit script's full gate logic.
#
# Understands the same two call shapes cnv-mtv-plan-gate.sh actually uses:
#   stub-bsod-check.sh [--strict] --cluster-scope-only <namespace>
#   stub-bsod-check.sh [--strict] --per-vm-only <namespace> <vm-name>
#
# Canned output is read from $STUB_FIXTURES_DIR:
#   cluster/<namespace>.txt   -- printed verbatim for --cluster-scope-only
#   vm/<namespace>/<vm>.txt   -- printed verbatim for --per-vm-only
# Missing fixture files are treated as a clean "[ OK ]" result (no output).
# Exit code mirrors the real audit script's contract: 1 if any "[FAIL]" line
# was printed, 0 otherwise (callers grep the printed text for their own
# FAIL/WARN counts; the exit code is a secondary/defensive signal).
# -----------------------------------------------------------------------------
set -uo pipefail

MODE=""
NS=""
VM=""
for arg in "$@"; do
  case "$arg" in
    --strict) ;;
    --cluster-scope-only) MODE="cluster" ;;
    --per-vm-only) MODE="vm" ;;
    *)
      if [ -z "$NS" ]; then NS="$arg"; elif [ -z "$VM" ]; then VM="$arg"; fi
      ;;
  esac
done

FIXTURES_DIR="${STUB_FIXTURES_DIR:?STUB_FIXTURES_DIR must be set}"

out=""
case "$MODE" in
  cluster)
    f="$FIXTURES_DIR/cluster/$NS.txt"
    [ -f "$f" ] && out="$(cat "$f")"
    ;;
  vm)
    f="$FIXTURES_DIR/vm/$NS/$VM.txt"
    if [ -f "$f" ]; then out="$(cat "$f")"; else out="  [ OK ] all gates clear (stub default)"; fi
    ;;
  *)
    echo "stub-bsod-check.sh: unrecognized invocation: $*" >&2
    exit 2
    ;;
esac

[ -n "$out" ] && printf '%s\n' "$out"
if printf '%s\n' "$out" | grep -q '\[FAIL\]'; then
  exit 1
fi
exit 0
