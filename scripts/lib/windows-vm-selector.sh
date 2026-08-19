#!/usr/bin/env bash
# windows-vm-selector.sh -- single-source the Windows-VM jq selector.
#
# R-10 (v0.19.0 unified review U-09). Builds the `select(...)` body used by every
# bash/jq consumer from shared/windows-vm-selector.json, so the clause SET (not
# just the trailing name regex) has one definition.
#
# WHY THIS EXISTS
# ---------------
# CLAUDE.md has always said four implementations "must agree", but agreement
# rested on human diligence and the contract test compared only the name regex.
# Three drifts existed simultaneously at v0.19.0 -- see the `_why` field in the
# JSON. One of them (`cnv-windows-exporter-fleet-install.sh`'s fallback) had no
# Windows filter at all and returned every VM in the namespace.
#
# STANDALONE MODE
# ---------------
# `cnv-qga-fleet-collect.sh` and `cnv-windows-exporter-fleet-install.sh` are
# documented as customer-shareable SINGLE SCRIPTS: they must work when neither
# this library nor the shared JSON is present. They therefore keep an embedded
# fallback selector, and `scripts/ci/validate-windows-vm-selector.py` asserts
# every embedded copy is byte-identical to what this library generates. The
# duplication is deliberate and machine-checked rather than merely commented.
#
# Sourced by: cnv-win-bsod-audit.sh, cnv-qga-fleet-collect.sh,
#             cnv-windows-exporter-fleet-install.sh,
#             must-gather/collection-scripts/common_bsod.sh
# Requires: jq
# shellcheck shell=bash

_WVS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null)" || _WVS_LIB_DIR="."

# Locate the shared config the same way every other shared/*.json consumer does:
# repo-relative first, then the container path used by the must-gather image.
wvs_config_path() {
  local c
  for c in "${BSOD_WIN_SELECTOR_OVERRIDE:-}" \
           "$_WVS_LIB_DIR/../../shared/windows-vm-selector.json" \
           "/usr/share/bsod-detection/shared/windows-vm-selector.json"; do
    [ -n "$c" ] && [ -f "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

# wvs_build_selector -- emit the jq `select(...)` expression on stdout.
#
# Returns 1 (emitting nothing) when the config or jq is unavailable, so callers
# can fall back to their embedded copy rather than silently selecting nothing --
# a selector that matches no VMs would report a clean fleet, which is the
# false-all-clear this framework exists to prevent.
wvs_build_selector() {
  local cfg
  cfg=$(wvs_config_path) || return 1
  command -v jq >/dev/null 2>&1 || return 1
  jq -r '
    (.os_hint_pattern) as $p
    | ([.os_hint_fields[] | "(\(.) // \"\" | test(\"\($p)\";\"i\"))"]
       + [.structural_predicates[]]
       + ["(\(.name_field) | test(\"\(.name_fallback_pattern)\";\"i\"))"])
    | "select(\n    " + join("\n    or ") + "\n  )"
  ' "$cfg" 2>/dev/null || return 1
}
