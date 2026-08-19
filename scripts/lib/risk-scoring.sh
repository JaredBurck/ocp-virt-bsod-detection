#!/usr/bin/env bash
# risk-scoring.sh -- shared risk-tier scoring for the bash gate layer.
#
# Implements the SAME weighted model as insights-rules/plugins/risk_scoring.py,
# reading the same shared/risk-scoring.json. Cross-layer agreement is enforced
# by shared/risk-tier-test-vectors.json (tests/test_risk_tier_contract.sh +
# insights-rules/tests/test_risk_tier_contract.py).
#
# WHY NOT A COUNT-BASED APPROXIMATION
# -----------------------------------
# The previous risk_tier() classified by counting FAILs/WARNs and claimed to
# "approximate" the Python thresholds. Measured against identical finding sets
# the two disagreed on 3 of 4 representative cases, in BOTH directions. Since
# Layer 4 (this script) is customer-facing while Layer 2 (Python) is Red Hat
# -only, a customer could be shown LOW for a VM Red Hat later called HIGH.
#
# INTEGER ARITHMETIC
# ------------------
# bash has no floating point, so all weights are pre-scaled by 100 in the shared
# JSON (*_x100). A finding's score in "centi-points" is:
#     (severity_x100 * domain_x100 * confidence_x100) / 10000
# Rank decay (0.5^rank) is an integer right-shift. Tier thresholds are compared
# in the same centi-point space. This is exact -- no rounding drift vs Python.
#
# FAIL-SAFE
# ---------
# If the shared config cannot be loaded, or a weight is unknown, this library
# rounds UP (toward higher risk) rather than down. A customer-facing migration
# gate must never under-report because a lookup missed.
#
# Sourced by scripts/cnv-win-bsod-audit.sh. Requires jq.
# shellcheck shell=bash

# --- config load -------------------------------------------------------------
# F15 (v0.17.0): BSOD_RISK_WEIGHTS_OVERRIDE lets an operator point at an
# alternate weights file (e.g. to tune domain/severity weights for a specific
# fleet) WITHOUT editing the canonical shared/risk-scoring.json that
# shared/risk-tier-test-vectors.json's cross-layer contract tests (this file
# vs. insights-rules/plugins/risk_scoring.py) are pinned against -- editing
# the canonical file in place would make every future contract-test failure
# ambiguous between "a real cross-layer drift" and "someone's local tuning".
# Checked FIRST, ahead of the canonical candidates, and only used if it
# actually exists -- an override pointing at a missing/typo'd path silently
# falls through to the canonical file rather than disabling scoring, since
# rs_load_config's own FAIL-SAFE contract (see this file's module header) is
# "degrade to no tier", not "let a bad override path do that by accident".
_RS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RS_CONFIG=""
for _rs_candidate in \
    "${BSOD_RISK_WEIGHTS_OVERRIDE:-}" \
    "$_RS_LIB_DIR/../../shared/risk-scoring.json" \
    "/usr/share/bsod-detection/shared/risk-scoring.json"; do
  if [ -n "$_rs_candidate" ] && [ -f "$_rs_candidate" ]; then
    RS_CONFIG="$_rs_candidate"
    break
  fi
done
if [ -n "${BSOD_RISK_WEIGHTS_OVERRIDE:-}" ] && [ "$RS_CONFIG" != "$BSOD_RISK_WEIGHTS_OVERRIDE" ]; then
  echo "WARN: BSOD_RISK_WEIGHTS_OVERRIDE=$BSOD_RISK_WEIGHTS_OVERRIDE not found -- falling back to the canonical shared/risk-scoring.json" >&2
fi

declare -A RS_SEVERITY=()
declare -A RS_DOMAIN=()
declare -A RS_CONFIDENCE=()
declare -A RS_GATE_DOMAIN=()
declare -A RS_KCS_TRIGGER=()
RS_TIER_CRITICAL=3000
RS_TIER_HIGH=1500
RS_TIER_MEDIUM=500
RS_DEFAULT_CONFIDENCE="GENERAL-KNOWLEDGE"
# Part of this library's public interface: sourcing scripts gate every scoring
# call on it (cnv-win-bsod-audit.sh x3, tests/test_risk_tier_contract.sh) so a
# missing or unparseable shared/risk-scoring.json degrades to "no tier" rather
# than to silently wrong tiers. shellcheck lints this file standalone in CI and
# cannot see those consumers, hence the explicit disable on the assignment in
# rs_load_config() rather than a rename or an export (the value is read by
# sourcing, never by a subprocess).
RS_CONFIG_LOADED=0

rs_load_config() {
  [ -n "$RS_CONFIG" ] || return 1
  command -v jq >/dev/null 2>&1 || return 1

  local kv
  while IFS=$'\t' read -r k v; do [ -n "$k" ] && RS_SEVERITY["$k"]="$v"; done < <(
    jq -r '.severity_weights_x100 | to_entries[] | "\(.key)\t\(.value)"' "$RS_CONFIG" 2>/dev/null)
  while IFS=$'\t' read -r k v; do [ -n "$k" ] && RS_DOMAIN["$k"]="$v"; done < <(
    jq -r '.domain_weights_x100 | to_entries[] | "\(.key)\t\(.value)"' "$RS_CONFIG" 2>/dev/null)
  while IFS=$'\t' read -r k v; do [ -n "$k" ] && RS_CONFIDENCE["$k"]="$v"; done < <(
    jq -r '.confidence_multipliers_x100 | to_entries[] | "\(.key)\t\(.value)"' "$RS_CONFIG" 2>/dev/null)
  while IFS=$'\t' read -r k v; do [ -n "$k" ] && RS_GATE_DOMAIN["$k"]="$v"; done < <(
    jq -r '.gate_domains | to_entries[] | "\(.key)\t\(.value)"' "$RS_CONFIG" 2>/dev/null)
  while IFS= read -r kv; do [ -n "$kv" ] && RS_KCS_TRIGGER["$kv"]=1; done < <(
    jq -r '.kcs_trigger_articles[]' "$RS_CONFIG" 2>/dev/null)

  RS_TIER_CRITICAL=$(jq -r '.tier_thresholds_x100.CRITICAL // 3000' "$RS_CONFIG" 2>/dev/null)
  RS_TIER_HIGH=$(jq -r '.tier_thresholds_x100.HIGH // 1500' "$RS_CONFIG" 2>/dev/null)
  RS_TIER_MEDIUM=$(jq -r '.tier_thresholds_x100.MEDIUM // 500' "$RS_CONFIG" 2>/dev/null)
  RS_DEFAULT_CONFIDENCE=$(jq -r '.default_confidence // "GENERAL-KNOWLEDGE"' "$RS_CONFIG" 2>/dev/null)

  # shellcheck disable=SC2034  # read by sourcing scripts; see declaration above
  [ "${#RS_SEVERITY[@]}" -gt 0 ] && RS_CONFIG_LOADED=1
  return 0
}
rs_load_config || true

# rs_confidence_for <kcs>
# L-2: KCS-VALIDATED only for articles that confirm a BSOD *trigger*. A
# comma-joined list (bash gates 17/19 cite several) qualifies if ANY member is a
# trigger article.
rs_confidence_for() {
  local kcs="${1:-}"
  [ -n "$kcs" ] || { echo "$RS_DEFAULT_CONFIDENCE"; return; }
  local IFS=','
  local part
  for part in $kcs; do
    part="${part// /}"
    if [ -n "${RS_KCS_TRIGGER[$part]:-}" ]; then echo "KCS-VALIDATED"; return; fi
  done
  echo "$RS_DEFAULT_CONFIDENCE"
}

# rs_score_finding <severity> <gate> <kcs> -> centi-points (integer)
rs_score_finding() {
  local severity="$1" gate="${2:-0}" kcs="${3:-}"
  local sev="${RS_SEVERITY[$severity]:-}"
  if [ -z "$sev" ]; then
    # Unknown severity: fail safe UPWARD -- treat as the highest weight rather
    # than silently scoring 0 and under-reporting.
    if [ "$severity" = "OK" ] || [ "$severity" = "PASS" ]; then echo 0; return; fi
    sev="${RS_SEVERITY[FAIL]:-1000}"
  fi
  [ "$sev" -eq 0 ] 2>/dev/null && { echo 0; return; }

  # N15: an unmapped gate/domain or a missing weight in a loaded-but-partial
  # config must fail UPWARD to the highest-weighted tier, matching the
  # documented FAIL-SAFE contract above -- "config"/100 (a middle-of-the-road
  # 1.0x weight) silently under-scored a gate this library couldn't classify,
  # the exact opposite of "rounds UP toward higher risk". Default to "crash"
  # (3.0x/300), same as risk_scoring.py's DOMAIN_WEIGHTS.get(domain, ...).
  local domain="${RS_GATE_DOMAIN[$gate]:-crash}"
  local dom="${RS_DOMAIN[$domain]:-${RS_DOMAIN[crash]:-300}}"
  local conf_name; conf_name=$(rs_confidence_for "$kcs")
  # Same fail-upward fix for an unrecognized confidence tier: default to
  # KCS-VALIDATED/100 (1.0x), not GENERAL-KNOWLEDGE/70 (0.7x).
  local conf="${RS_CONFIDENCE[$conf_name]:-${RS_CONFIDENCE[KCS-VALIDATED]:-100}}"

  echo $(( sev * dom * conf / 10000 ))
}

# --- per-VM accumulation with per-domain rank decay --------------------------
declare -A RS_DOMAIN_SCORES=()

rs_reset() { RS_DOMAIN_SCORES=(); }

# rs_add <severity> <gate> <kcs>
rs_add() {
  local severity="$1" gate="${2:-0}" kcs="${3:-}"
  local score; score=$(rs_score_finding "$severity" "$gate" "$kcs")
  [ "${score:-0}" -gt 0 ] 2>/dev/null || return 0
  # N15: mirror rs_score_finding's fail-upward domain default so an unmapped
  # gate's score is bucketed (for rank-decay/domain_breakdown purposes) under
  # the same domain it was actually scored against.
  local domain="${RS_GATE_DOMAIN[$gate]:-crash}"
  RS_DOMAIN_SCORES["$domain"]="${RS_DOMAIN_SCORES[$domain]:-} $score"
}

# rs_total -> total centi-points, applying 0.5^rank decay within each domain
rs_total() {
  # All locals are _rs_-prefixed: this library is sourced into the gate script's
  # shell, and an unprefixed name (e.g. `raw`) collides with the caller's own
  # locals -- harmless while both stay `local`, but a latent trap.
  local total=0 domain rank
  local -a _rs_raw=() _rs_scores=()
  local _rs_s
  for domain in "${!RS_DOMAIN_SCORES[@]}"; do
    # Sort this domain's scores descending so the highest-value finding takes
    # full weight and duplicates of the same root cause decay -- matching
    # risk_scoring.py's `sorted(..., reverse=True)` then `0.5 ** rank`.
    # Scores are accumulated as a space-separated string; split explicitly with
    # read -ra rather than relying on unquoted expansion.
    read -ra _rs_raw <<< "${RS_DOMAIN_SCORES[$domain]}"
    mapfile -t _rs_scores < <(printf '%s\n' "${_rs_raw[@]}" | sort -rn)
    rank=0
    for _rs_s in "${_rs_scores[@]}"; do
      [ -n "$_rs_s" ] || continue
      total=$(( total + (_rs_s >> rank) ))
      rank=$(( rank + 1 ))
      [ "$rank" -gt 30 ] && rank=30   # guard against absurd shift counts
    done
  done
  echo "$total"
}

# rs_tier <total_centi> -> CRITICAL|HIGH|MEDIUM|LOW
rs_tier() {
  local total="${1:-0}"
  if [ "$total" -ge "$RS_TIER_CRITICAL" ]; then echo "CRITICAL"
  elif [ "$total" -ge "$RS_TIER_HIGH" ]; then echo "HIGH"
  elif [ "$total" -ge "$RS_TIER_MEDIUM" ]; then echo "MEDIUM"
  else echo "LOW"; fi
}

# rs_tier_display <total_centi> -> "TIER (score=NN.N)"
rs_tier_display() {
  local total="${1:-0}"
  printf '%s (score=%d.%02d)' "$(rs_tier "$total")" $(( total / 100 )) $(( total % 100 ))
}
