#!/usr/bin/env bash
#
# test_qga_harden_staging_dir.sh
# -----------------------------------------------------------------------------
# Offline unit-style regression test for harden_guest_staging_dir() (L-9 ACL
# hardening) in scripts/cnv-qga-fleet-collect.sh:349-387.
#
# N20 (v0.15.0 Phase 6): this function needs a live Windows guest via QGA to
# exercise for real, and no VM on the reference cluster has a connected
# QEMU Guest Agent (see CHANGELOG.md's N7/N8 live-validation notes) -- so it
# has shipped with zero automated coverage since it was introduced. A
# regression here (e.g. a broken grep pattern that stops detecting a
# leftover `BUILTIN\Users:` ACE, or a change that swaps qga_exec_capture for
# qga_exec and silently loses the ability to fail closed) would not be
# caught by any existing test.
#
# v0.19.0: live QGA testing against real bsod-test namespace VMs (unlike when
# this comment above was first written) surfaced exactly the kind of
# regression this test couldn't see: the function originally built each
# icacls call as a single `cmd.exe /c "icacls \"$dir\" ..."` string with the
# path manually quoted. QEMU-GA's argv-to-command-line escaping assumes
# standard MSVCRT `\"`-escaping, but cmd.exe's own /c string parser does NOT
# treat `\"` as an escape -- every literal `"` just toggles quote-mode,
# backslash is never special to it -- so the two disagreed on where the
# quoted region ended, and `icacls "C:\DebugInfo" ...` sent this way came
# back "The filename, directory name, or volume label syntax is incorrect"
# on a real guest. The command still exited 0 (a mis-parsed builtin invocation
# that does nothing is not an *error* from cmd.exe's perspective), so this
# stubbed test -- which only asserts exit codes and literal command strings,
# never real cmd.exe parsing -- passed the whole time regardless. Fixed by
# passing $dir as its own argv element (never re-quoted) and invoking
# icacls.exe directly instead of through cmd.exe /c; scenario (d) below now
# asserts the new argv-based call shape.
#
# This mirrors the tests/mock-oc.sh / tests/stub-*.sh pattern already used
# for guest/cluster interactions elsewhere in the suite: rather than
# sourcing the whole script (which parses argv and runs its collection loop
# top-level, requiring real `oc`/QGA), it extracts *only* the
# harden_guest_staging_dir function body by line range and sources that in
# isolation, with qga_exec/qga_exec_capture stubbed to return
# scenario-scripted guest-command output. This can't replace live
# verification of the actual icacls semantics against a real Windows ACL
# engine, but it locks in the function's control flow and the exact command
# strings it sends to the guest, closing the "silent regression" risk called
# out in the finding.
#
# Usage: tests/test_qga_harden_staging_dir.sh
# Exit code: 0 if every scenario matches its expected result, else 1.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="$REPO_ROOT/scripts/cnv-qga-fleet-collect.sh"

if [ ! -f "$TARGET" ]; then
  echo "FAIL: $TARGET not found"
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }

# Extract the function verbatim from the source file so this test can never
# silently drift out of sync with what actually ships (same rationale as
# test_windows_vm_name_regex.sh's regex extraction).
FUNC_SRC="$(sed -n '/^harden_guest_staging_dir() {$/,/^}$/p' "$TARGET")"
if [ -z "$FUNC_SRC" ]; then
  echo "FAIL: could not extract harden_guest_staging_dir() from $TARGET"
  exit 1
fi
# shellcheck disable=SC2086,SC1090,SC1091
eval "$FUNC_SRC"
if ! declare -F harden_guest_staging_dir >/dev/null; then
  echo "FAIL: harden_guest_staging_dir did not source correctly"
  exit 1
fi

# shellcheck disable=SC2034  # consumed by the eval'd function body, not visible to shellcheck
GUEST_OUT_DIR='C:\DebugInfo'
log() { :; }  # silence during tests; failures are asserted via return code

CALL_LOG=""
QGA_EXEC_CAPTURE_OUTPUT=""

# Stub for qga_exec: records every invocation's full argv (joined with a
# single space, one call per line) and always "succeeds" (mirrors
# mkdir/setowner/inheritance calls in real use, which the function
# intentionally ignores the exit code of -- verification happens via the
# qga_exec_capture readback below, not via these calls). Args are recorded as
# a space-joined argv list, not a single command string: the function passes
# the guest path and each icacls flag as separate argv elements (never
# re-quoted into one cmd.exe /c string -- see the v0.19.0 comment above for
# why), skipping ns/pod/domain/path (the first 4 positional args) since
# assertions only care about the guest-side command shape.
qga_exec() {
  shift 4
  CALL_LOG="${CALL_LOG}$*"$'\n'
  echo "0"
}

# Stub for qga_exec_capture: returns the scenario-scripted icacls output
# regardless of arguments (the function only calls this once, for the
# read-back `icacls "$dir"`).
qga_exec_capture() {
  printf '%s' "$QGA_EXEC_CAPTURE_OUTPUT"
}

reset_stubs() {
  CALL_LOG=""
  QGA_EXEC_CAPTURE_OUTPUT="$1"
}

# --- Scenario (a): clean ACL after hardening -> success ---
reset_stubs 'C:\DebugInfo NT AUTHORITY\SYSTEM:(OI)(CI)(F)
             BUILTIN\Administrators:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files'
if harden_guest_staging_dir ns pod domain; then
  pass "(a) clean ACL (SYSTEM + Administrators only) returns 0"
else
  fail "(a) clean ACL should return 0, got non-zero"
fi

# --- Scenario (b): leftover BUILTIN\Users ACE -> hard failure ---
reset_stubs 'C:\DebugInfo NT AUTHORITY\SYSTEM:(OI)(CI)(F)
             BUILTIN\Administrators:(OI)(CI)(F)
             BUILTIN\Users:(OI)(CI)(RX)'
if harden_guest_staging_dir ns pod domain; then
  fail "(b) ACL still granting BUILTIN\\Users should return non-zero, got 0"
else
  pass "(b) ACL still granting BUILTIN\\Users returns non-zero"
fi

# --- Scenario (b2): leftover Everyone ACE -> hard failure ---
reset_stubs 'C:\DebugInfo Everyone:(OI)(CI)(F)'
if harden_guest_staging_dir ns pod domain; then
  fail "(b2) ACL still granting Everyone should return non-zero, got 0"
else
  pass "(b2) ACL still granting Everyone returns non-zero"
fi

# --- Scenario (b3): leftover well-known SID (S-1-5-11, Authenticated Users) ---
reset_stubs 'C:\DebugInfo S-1-5-11:(OI)(CI)(RX)'
if harden_guest_staging_dir ns pod domain; then
  fail "(b3) ACL still granting Authenticated Users SID should return non-zero, got 0"
else
  pass "(b3) ACL still granting Authenticated Users SID returns non-zero"
fi

# --- Scenario (c): icacls read-back returns nothing -> fail closed ---
reset_stubs ''
if harden_guest_staging_dir ns pod domain; then
  fail "(c) empty/unreadable ACL should fail closed (non-zero), got 0"
else
  pass "(c) empty/unreadable ACL fails closed (non-zero)"
fi

# --- Scenario (d): exact icacls command strings are well-formed ---
reset_stubs 'C:\DebugInfo NT AUTHORITY\SYSTEM:(OI)(CI)(F)'
harden_guest_staging_dir ns pod domain >/dev/null 2>&1 || true

if printf '%s' "$CALL_LOG" | grep -qF '/c mkdir C:\DebugInfo\lib'; then
  pass "(d) mkdir command targets the correct staging subdirectory"
else
  fail "(d) mkdir command missing or malformed: $CALL_LOG"
fi

# The path must appear as its own argv element with NO surrounding quotes --
# see the v0.19.0 comment above for why re-quoting it breaks on a real guest.
if printf '%s' "$CALL_LOG" | grep -qF 'C:\DebugInfo /setowner *S-1-5-32-544 /T /C'; then
  pass "(d) /setowner command reclaims ownership to BUILTIN\\Administrators SID"
else
  fail "(d) /setowner command missing or malformed: $CALL_LOG"
fi

# NOTE the absence of /T on this grant, and that it is asserted deliberately.
#
# (OI)(CI) are CONTAINER inheritance flags. Applying them to leaf FILES with /T
# -- as this did until v0.27.0 -- combines with /inheritance:r stripping each
# file's inherited ACEs to leave the file with an EMPTY DACL: openable by
# nobody, not even SYSTEM. The practical effect was that --stage worked exactly
# ONCE per guest; every later run bricked the previously-staged collector and
# staging then failed with "cannot open ... for write" permanently.
#
# Reproduced on a live 5-VM fleet: the single guest with a pre-existing
# C:\DebugInfo failed to re-stage while four fresh ones succeeded, and icacls
# on that file listed no ACEs at all.
if printf '%s' "$CALL_LOG" | grep -qF 'C:\DebugInfo /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F /C'; then
  pass "(d) /inheritance:r + /grant:r command grants only SYSTEM + Administrators SIDs"
else
  fail "(d) /inheritance:r + /grant:r command missing or malformed: $CALL_LOG"
fi

if printf '%s' "$CALL_LOG" | grep -qF '/inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F /T'; then
  fail "(d) the (OI)(CI) grant carries /T -- that is the bug that empties every pre-existing file's DACL and makes --stage single-use per guest: $CALL_LOG"
else
  pass "(d) the (OI)(CI) grant is NOT applied recursively to files"
fi

# Children must be reset so they re-inherit from the hardened parent. This is
# also the repair path for a guest already bricked by the old /T behaviour.
if printf '%s' "$CALL_LOG" | grep -qF 'C:\DebugInfo\* /reset /T /C'; then
  pass "(d) existing children are reset to re-inherit from the hardened parent"
else
  fail "(d) missing the child /reset pass -- pre-existing files keep whatever DACL they had: $CALL_LOG"
fi

if printf '%s' "$CALL_LOG" | grep -qF '"'; then
  fail "(d) a guest path or icacls flag was re-quoted -- this is exactly the pattern that silently no-ops on a real Windows guest: $CALL_LOG"
else
  pass "(d) no guest-side argument is wrapped in literal double-quotes"
fi

# --- (e) R-17 / U-15: the exporter installer must harden staging DIRECTORIES
# before writing into them ------------------------------------------------------
#
# Asserted as a source-order invariant rather than behaviourally: the defect was
# an ORDERING one (mkdir -> write every file -> harden each file), which leaves a
# window where an unprivileged guest process can pre-create or replace content
# this script subsequently EXECUTES as SYSTEM. Per-file hardening also cannot
# undo a directory a low-priv user already owns, since an owner can rewrite any
# DACL applied later. A behavioural test would need a real Windows guest; the
# ordering is what actually has to hold, and it is checkable here.
EXPORTER="$REPO_ROOT/scripts/cnv-windows-exporter-fleet-install.sh"
if [ -f "$EXPORTER" ]; then
  # grep -F: these are literal source fragments, not patterns. Using -F also
  # sidesteps SC2016, which cannot tell an intentional literal '$' in a search
  # string from an accidentally unexpanded variable.
  _harden_line=$(grep -nF '_STAGE_DIR_MARKER' "$EXPORTER" | head -1 | cut -d: -f1)
  _write_line=$(grep -nF 'qga_file_write ' "$EXPORTER" | grep -v '^[0-9]*:qga_file_write()' | head -1 | cut -d: -f1)
  if [ -z "$_harden_line" ]; then
    fail "(e) exporter installer does not harden staging directories at all"
  elif [ -z "$_write_line" ]; then
    fail "(e) could not locate the exporter installer's first qga_file_write"
  elif [ "$_harden_line" -lt "$_write_line" ]; then
    pass "(e) staging directories are hardened (line $_harden_line) BEFORE the first file write (line $_write_line)"
  else
    fail "(e) staging directories are hardened at line $_harden_line, AFTER the first file write at line $_write_line -- this is the LPE race window R-17 closed"
  fi

  if grep -q '/setowner" "\*S-1-5-32-544"' "$EXPORTER"; then
    pass "(e) directory hardening reclaims ownership first (an owner outranks any DACL set afterwards)"
  else
    fail "(e) directory hardening does not reclaim ownership -- a pre-created dir owned by a low-priv user can rewrite the DACL"
  fi
fi

# --- (f) R-40 / N-04: the scheduled collector must RE-harden its textfile
# directory on every run --------------------------------------------------------
#
# install-windows-exporter.ps1 hardens once at install time, but
# bsod-textfile-collector.ps1 runs as SYSTEM from a scheduled task every 5
# minutes forever. Its `New-Item -Force` recreates the directory with default
# (Users-writable) inherited ACLs whenever it is missing, then writes .prom files
# into it -- reopening the exact window Wave 2 closed, on a 5-minute loop.
# windows_exporter exposes whatever it finds there as metrics, so a writable
# textfile dir is a metric-injection surface.
#
# Asserted structurally (pwsh is not available in this harness): the hardening
# call must exist, must come before any file write, and must reuse the shared
# helper rather than a second copy of the ACL rules.
COLLECTOR="$REPO_ROOT/windows-exporter/bsod-textfile-collector.ps1"
if [ -f "$COLLECTOR" ]; then
  _c_harden=$(grep -nF '_TEXTFILE_HARDEN_MARKER' "$COLLECTOR" | head -1 | cut -d: -f1)
  _c_write=$(grep -nE 'Move-Item|Set-Content|Out-File' "$COLLECTOR" | head -1 | cut -d: -f1)

  if [ -z "$_c_harden" ]; then
    fail "(f) collector never re-hardens \$TextfileDir -- the 5-minute New-Item -Force loop leaves it Users-writable"
  elif [ -n "$_c_write" ] && [ "$_c_harden" -ge "$_c_write" ]; then
    fail "(f) collector hardens at line $_c_harden, AFTER its first write at line $_c_write"
  else
    pass "(f) collector re-hardens \$TextfileDir (line $_c_harden) before any write (line ${_c_write:-none})"
  fi

  # Must reuse the shared helper, not re-implement the rules.
  if grep -q 'lib.Protect-GuestStagingDir.ps1' "$COLLECTOR"; then
    pass "(f) collector sources the shared ACL helper rather than duplicating the rule set"
  else
    fail "(f) collector does not source scripts/lib/Protect-GuestStagingDir.ps1 -- a second copy of the ACL rules is exactly the drift this repo keeps finding"
  fi

  # The helper must be staged where the collector will actually look for it.
  INSTALLER="$REPO_ROOT/windows-exporter/install-windows-exporter.ps1"
  if grep -q 'protectDest' "$INSTALLER"; then
    pass "(f) installer stages the ACL helper into the persistent lib/ the collector reads"
  else
    fail "(f) installer does not stage Protect-GuestStagingDir.ps1 into \$libDir -- the collector will warn and skip hardening on every run"
  fi
fi

# --- (g) R-41 / N-05: re-running the installer must be able to NARROW the
# firewall rule --------------------------------------------------------------
#
# The installer previously skipped any firewall change when a rule with the
# expected DisplayName already existed ("leaving as-is"). The script's own
# comment calls that rule "the actual security boundary here" for a plaintext,
# unauthenticated exporter -- so an operator who installed with the zero-config
# default (-FirewallRemoteAddress Any) and re-ran to narrow it got no error and
# no effect, failing in the direction of leaving access open.
INSTALLER="$REPO_ROOT/windows-exporter/install-windows-exporter.ps1"
if [ -f "$INSTALLER" ]; then
  if grep -q 'Set-NetFirewallRule' "$INSTALLER"; then
    pass "(g) installer updates an existing firewall rule in place (Set-NetFirewallRule)"
  else
    fail "(g) installer has no Set-NetFirewallRule -- a re-run cannot narrow -RemoteAddress/-Profile"
  fi

  # Comment lines are excluded: the fix's own comment quotes the old string when
  # explaining what changed, and matching that would make the test fail on the
  # documentation of its own fix.
  if grep -v '^\s*#' "$INSTALLER" | grep -q 'leaving as-is'; then
    fail "(g) installer still short-circuits with 'leaving as-is' -- a requested narrowing is silently discarded"
  else
    pass "(g) no silent skip-if-exists branch remains in executable code"
  fi

  # An operator must be able to SEE that the narrowing took effect.
  if grep -qE 'profile: .*->|remote:  .*->' "$INSTALLER"; then
    pass "(g) installer logs before -> after values so the change is verifiable"
  else
    fail "(g) installer does not log before/after firewall scope -- an operator cannot confirm the narrowing happened"
  fi
fi

# --- (h) H3: exporter installer fail-closed ACL readback ---------------------
#
# Sibling cnv-qga-fleet-collect.sh already fail-closes harden_guest_staging_dir
# via qga_exec_capture + leftover-Users regex. The installer duplicated the
# icacls argv but only checked qga_exec's exit code, so a leftover Users ACE
# (icacls still exits 0) would proceed to execute the MSI as SYSTEM.
# Extract qga_acl_readback_ok the same way this harness extracts
# harden_guest_staging_dir -- lock the control flow without a live guest.
EXPORTER="$REPO_ROOT/scripts/cnv-windows-exporter-fleet-install.sh"
ACL_FUNC_SRC="$(sed -n '/^qga_acl_readback_ok() {$/,/^}$/p' "$EXPORTER")"
if [ -z "$ACL_FUNC_SRC" ]; then
  fail "(h) could not extract qga_acl_readback_ok() from $EXPORTER"
else
  eval "$ACL_FUNC_SRC"
  if ! declare -F qga_acl_readback_ok >/dev/null; then
    fail "(h) qga_acl_readback_ok did not source correctly"
  else
    # Stub capture for the installer helper: record argv and return scripted output.
    QGA_EXEC_CAPTURE_OUTPUT=""
    QGA_EXEC_CAPTURE_LOG=""
    qga_exec_capture() {
      shift 4
      QGA_EXEC_CAPTURE_LOG="${QGA_EXEC_CAPTURE_LOG}$*"$'\n'
      printf '%s' "$QGA_EXEC_CAPTURE_OUTPUT"
    }

    QGA_EXEC_CAPTURE_OUTPUT='C:\Temp\windows-exporter NT AUTHORITY\SYSTEM:(OI)(CI)(F)
             BUILTIN\Administrators:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files'
    if qga_acl_readback_ok ns pod domain 'C:\Temp\windows-exporter'; then
      pass "(h) clean SYSTEM+Administrators DACL continues"
    else
      fail "(h) clean DACL should return 0, got non-zero"
    fi

    QGA_EXEC_CAPTURE_OUTPUT='C:\Temp\windows-exporter NT AUTHORITY\SYSTEM:(F)
             BUILTIN\Users:(RX)'
    if qga_acl_readback_ok ns pod domain 'C:\Temp\windows-exporter'; then
      fail "(h) leftover BUILTIN\\Users ACE should abort, got 0"
    else
      pass "(h) leftover BUILTIN\\Users ACE aborts staging"
    fi

    QGA_EXEC_CAPTURE_OUTPUT=''
    if qga_acl_readback_ok ns pod domain 'C:\Temp\windows-exporter'; then
      fail "(h) empty capture should abort, got 0"
    else
      pass "(h) empty ACL capture fails closed"
    fi

    # R0.2 / R0.7: readback must use qga_exec_capture, not exit-code-only qga_exec.
    if grep -qE 'acl=\$\(qga_exec_capture ' "$EXPORTER"; then
      pass "(h) ACL readback uses qga_exec_capture (not qga_exec)"
    else
      fail "(h) ACL readback does not call qga_exec_capture -- exit-code-only qga_exec cannot see leftover Users ACEs"
    fi
    _inherit_blocks=$(grep -cF '/inheritance:r' "$EXPORTER" || true)
    _readback_calls=$(grep -cF 'qga_acl_readback_ok ' "$EXPORTER" || true)
    # Two call sites (directory loop + per-file loop) plus the function
    # definition does not contain a trailing space after the name in a call.
    if [ "$_readback_calls" -ge 2 ]; then
      pass "(h) qga_acl_readback_ok is invoked after icacls hardening ($_readback_calls call(s); $_inherit_blocks inheritance block(s))"
    else
      fail "(h) expected >=2 qga_acl_readback_ok call sites (dir + per-file), found $_readback_calls"
    fi
  fi
fi

echo
echo "=============================================="
echo " test_qga_harden_staging_dir.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
