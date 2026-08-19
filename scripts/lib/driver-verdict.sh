#!/usr/bin/env bash
# driver-verdict.sh -- stream-aware driver version verdict logic.
# Single source of truth for the bash layer. Sourced by:
#   - scripts/cnv-win-bsod-audit.sh (production)
#   - tests/test_bash_verdict.sh (CI harness)
#
# Expects callers to set: STREAM_MAX, STREAM_FAIL, STREAM_WARN,
#   TOOLING_FLOOR, DRIVER_BASELINE
# Sets: DRIVER_VERDICT ("FAIL", "WARN", or "PASS")

# version_gte: return 0 (true) if $1 >= $2 using sort -V
version_gte() {
  [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -1)" = "$2" ]
}

# evaluate_driver_version_stream: apply stream-aware threshold logic.
# Called by Gate 15 in cnv-win-bsod-audit.sh when guest evidence exists under
# BSOD_GUEST_EVIDENCE_DIR (QGA/collector artifacts). Also used by the bash
# verdict CI harness.
# Usage: evaluate_driver_version_stream <version>
# Sets DRIVER_VERDICT to "FAIL", "WARN", or "PASS"
#
# DRIVER_VERDICT / DRIVER_VERDICT_REASON are this library's RETURN VALUES --
# bash functions cannot return strings, so callers read these globals
# (cnv-win-bsod-audit.sh Gate 15, tests/test_bash_verdict.sh). shellcheck lints
# this file standalone and cannot see those consumers, so it reports them as
# unused. Suppressed rather than exported: they are read by sourcing, never by
# a subprocess.
# shellcheck disable=SC2034
evaluate_driver_version_stream() {
  local ver="$1"
  DRIVER_VERDICT="PASS"
  DRIVER_VERDICT_REASON=""
  if [ -z "$ver" ]; then
    DRIVER_VERDICT="WARN"
    DRIVER_VERDICT_REASON="empty_version"
    return
  fi
  # R-01 (v0.19.0 unified review U-01): FORMAT ANCHOR -- must run before any
  # threshold comparison.
  #
  # version_gte() ranks with `sort -V`, in which a non-numeric-leading string
  # sorts ABOVE every real version. Such a value therefore satisfied every
  # threshold comparison below and fell through to this function's initial
  # DRIVER_VERDICT="PASS" -- so 'N/A', 'unknown', 'virtio-win-1.9.20' and
  # 'v1.9.20' all graded PASS on the framework's single most important guest
  # check, while Python's parse_version() correctly returned None -> WARN for
  # the same inputs.
  #
  # Note this is the same bug CLASS as v0.7.0's V7-1 (a wrong-identity version
  # string producing a false PASS). The `major > 50` guard added for V7-1 is
  # immediately below and only covers NUMERIC majors -- its own non-numeric
  # arm is a deliberate no-op, which is precisely the hole this anchor closes.
  # Fail SAFE (WARN), never open: an unparseable version is unassessed
  # evidence, and this framework's first principle is that a PASS must never
  # be reported on evidence that was never successfully collected.
  #
  # Only the UPSTREAM portion is validated. A real RPM NEVRA suffix
  # ('1.9.57-2.el9', '1.9.41-1') is legitimate collector output and must keep
  # grading as before, so strip from the first '-' and anchor the remainder.
  # 'virtio-win-1.9.20' strips to 'virtio' and is correctly rejected.
  # Threshold comparisons below still use the ORIGINAL string so `sort -V`
  # ordering of release suffixes is unchanged.
  local _dv_upstream="${ver%%-*}"
  case "$_dv_upstream" in
    ''|*[!0-9.]*|.*|*.|*..*)
      DRIVER_VERDICT="WARN"
      DRIVER_VERDICT_REASON="unparseable_version"
      return
      ;;
    *.*) : ;;
    *)
      # Bare major ('2') -- too little precision to grade against an x.y.z
      # threshold. Two components ('1.9') is the documented minimum.
      DRIVER_VERDICT="WARN"
      DRIVER_VERDICT_REASON="unparseable_version"
      return
      ;;
  esac
  # Sanity guard: a Win32_PnPSignedDriver "binary" DriverVersion (e.g.
  # 100.85.104.20700 -- confirmed real-world via Red Hat Bugzilla #1998933 for
  # the VirtIO SCSI driver) is easy to mistake for the virtio-win *package*
  # version (e.g. 1.9.57): both are dotted-numeric strings. virtio-win package
  # majors are 1.x for the foreseeable future, so major > 50 unambiguously
  # signals the wrong identity was captured upstream. Never let this silently
  # evaluate as PASS (sort -V would otherwise treat 100.x as "way above" any
  # real threshold).
  local major="${ver%%.*}"
  case "$major" in
    ''|*[!0-9]*) : ;;
    *)
      if [ "$major" -gt 50 ]; then
        DRIVER_VERDICT="WARN"
        DRIVER_VERDICT_REASON="binary_format_version"
        return
      fi
      ;;
  esac
  if [ -n "$STREAM_MAX" ] && version_gte "$ver" "$STREAM_MAX"; then
    # F-03: tag the reason so the caller can score this in the weight-0
    # `platform` domain (gate 22) rather than `driver` (gate 15). Without a
    # reason this fell through to Gate 15's generic WARN message and scored
    # 4.50 -- identically on every VM of a capped stream, for a condition no
    # VM-level action can clear. Python carries the same distinction via its
    # own rule_id (BSOD_PLATFORM_DRIVER_STREAM_CAPPED); keep the two in sync.
    DRIVER_VERDICT="WARN"
    DRIVER_VERDICT_REASON="at_stream_max"
    return
  fi
  if [ -n "$STREAM_FAIL" ] && ! version_gte "$ver" "$STREAM_FAIL"; then
    DRIVER_VERDICT="FAIL"
    return
  fi
  if [ -n "$STREAM_WARN" ] && ! version_gte "$ver" "$STREAM_WARN"; then
    DRIVER_VERDICT="WARN"
    return
  fi
  if ! version_gte "$ver" "$TOOLING_FLOOR"; then
    # H-2: on capped streams where max < tooling floor, FAIL is unactionable
    if [ -n "$STREAM_MAX" ] && ! version_gte "$STREAM_MAX" "$TOOLING_FLOOR"; then
      DRIVER_VERDICT="WARN"
    else
      DRIVER_VERDICT="FAIL"
    fi
    return
  fi
  if ! version_gte "$ver" "$DRIVER_BASELINE"; then
    DRIVER_VERDICT="WARN"
    return
  fi
}

# evaluate_guest_os_driver_compatibility: N-06 (Wave 7, R-47) -- a SEPARATE
# axis from evaluate_driver_version_stream above, deliberately not fused into
# it. That function answers "is this driver version current for the
# host-stream running it"; this one answers "is this guest OS a Red Hat
# Certified OpenShift Virtualization guest at all (KCS 4234591), and does ANY
# virtio-win '1.9.x' package this framework tracks even claim to support it",
# which is independent of the specific version reported -- for every legacy
# OS this framework recognizes (XP, Server 2003/2008/2012, Windows 7/8/8.1),
# KCS 4234591 places it outside the Certified tier (either "Known to work" +
# EOL, or absent from all four support tiers entirely), so the answer is "no"
# regardless of driver_version, even if driver_version was never collected.
# See shared/virtio-win-guest-os-support.json's
# _incompatible_with_any_tracked_version_semantics for why this is not
# modeled as a numeric ceiling of "0.0.0".
#
# Usage: evaluate_guest_os_driver_compatibility <os_hint> [driver_version]
# Sets OS_COMPAT_VERDICT ("INCOMPATIBLE" or ""), OS_COMPAT_OS_NAME,
# OS_COMPAT_CEILING (last supported package version, if any is established).
# Requires OS_SUPPORT_FILE (shared/virtio-win-guest-os-support.json or the
# container path) and jq; fails SILENT (empty verdict), not fail-open on
# DRIVER_VERDICT above -- this is an ADDITIONAL finding on top of that
# verdict, never a substitute for it.
# shellcheck disable=SC2034
evaluate_guest_os_driver_compatibility() {
  local os_hint="$1"
  local ver="${2:-}"
  OS_COMPAT_VERDICT=""
  OS_COMPAT_OS_NAME=""
  OS_COMPAT_CEILING=""
  [ -z "$os_hint" ] && return 0
  [ -z "${OS_SUPPORT_FILE:-}" ] && return 0
  command -v jq >/dev/null 2>&1 || return 0

  local match_key
  match_key=$(jq -r --arg os "$os_hint" '
    . as $root
    | ($root._match_order // [])[] as $k
    | ($root.os_support[$k].match_pattern) as $p
    | select($os | test($p; "i"))
    | $k
  ' "$OS_SUPPORT_FILE" 2>/dev/null | head -1)
  [ -z "$match_key" ] && return 0

  local incompatible ceiling display
  incompatible=$(jq -r --arg k "$match_key" '.os_support[$k].incompatible_with_any_tracked_version' "$OS_SUPPORT_FILE" 2>/dev/null)
  ceiling=$(jq -r --arg k "$match_key" '.os_support[$k].last_supported_package_version // empty' "$OS_SUPPORT_FILE" 2>/dev/null)
  display=$(jq -r --arg k "$match_key" '.os_support[$k].display_name' "$OS_SUPPORT_FILE" 2>/dev/null)
  OS_COMPAT_OS_NAME="$display"
  OS_COMPAT_CEILING="$ceiling"

  if [ "$incompatible" = "true" ]; then
    OS_COMPAT_VERDICT="INCOMPATIBLE"
    return 0
  fi
  # Ceiling-based path: no os_support token carries a non-null
  # last_supported_package_version as of this writing (win7/win8/win81 are
  # all CEILING_NOT_YET_ESTABLISHED -- see the shared JSON's citations), so
  # this branch is currently unreached in production. Implemented now so a
  # future citation only requires filling in the JSON value, not new code
  # here. Only compare against a version string that already looks
  # dotted-numeric -- evaluate_driver_version_stream's own format anchor is
  # the authority on parseability; this function does not duplicate it.
  case "$ver" in
    *[0-9]*.*[0-9]*)
      if [ -n "$ceiling" ] && ! version_gte "$ceiling" "$ver"; then
        OS_COMPAT_VERDICT="INCOMPATIBLE"
      fi
      ;;
  esac
}
