#!/usr/bin/env python3
"""Enforce the audit-consumer inventory in shared/audit-consumers.json.

Three consecutive review rounds found the same failure shape: a capability is
built correctly at its source and the wiring to ONE MORE CONSUMER is left
incomplete. The UNKNOWN severity contract was fixed in the rules (v0.15.0) but
not in the Tekton PreHook Job (H2, v0.16.0), which decided on the raw exit code
and therefore migrated VMs the framework had never assessed.

H2's fix -- an opt-in `--fail-on-unknown` -- closes that instance but on its own
recreates the trap: every FUTURE unattended consumer must remember the flag.
This guard replaces "remember" with "cannot forget":

  1. Any file that invokes cnv-win-bsod-audit.sh (or $BSOD_CHECK_CMD) and is
     NOT declared in the inventory fails CI. Adding a consumer forces you to
     state how it treats UNKNOWN.
  2. Any declared consumer with decides_via=exit_code AND unattended=true must
     actually contain the flags it declares it requires -- so the declaration
     cannot drift from the artifact.
  3. Stale entries (declared path no longer exists) fail, so the inventory
     cannot rot into fiction.

Usage:
    python3 scripts/ci/validate-unattended-consumers.py
Exit: 0 clean, 1 violation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = REPO_ROOT / "shared" / "audit-consumers.json"

# Where a consumer could plausibly live.
#
# Excluded on purpose:
#   tests/          -- exercise the audit rather than gate on it, and are the
#                      one place a deliberately "wrong" invocation is expected
#                      (see tests/test_prehook_contract.sh).
#   alerts/, acm/   -- PrometheusRule and Policy manifests are pure DATA and
#                      cannot execute anything. They name the script only as
#                      runbook prose for a human ("1. Run: cnv-win-bsod-audit.sh
#                      <ns> <vm>"), which is not a programmatic consumer.
SCAN_GLOBS = (
    "scripts/*.sh",
    "scripts/lib/*.sh",
    "must-gather/collection-scripts/*",
    "tekton/*.yaml",
    "Dockerfile*",
    ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
)

# The audit script itself is not its own consumer.
SELF = "scripts/cnv-win-bsod-audit.sh"

# An INVOCATION, not a mention. Excludes comment lines and prose (alert runbook
# annotations name the script as an instruction to a human, which is not a
# programmatic consumer).
INVOKE_RE = re.compile(
    r"""(?:
          # direct execution
          ^\s*(?:bash|sh)\s+["']?\$?\{?[\w/.$-]*cnv-win-bsod-audit\.sh
        | (?:^|["';|&]|&&|\|\||\bbash\s|\bsh\s)\s*[\w/.$-]*/?cnv-win-bsod-audit\.sh[\s"']
        | \$\(\s*["']?[\w/.$-]*cnv-win-bsod-audit\.sh
        | ENTRYPOINT\s*\[\s*"[^"]*cnv-win-bsod-audit\.sh"
          # execution through a variable holding the path. The assignment is
          # the reliable signal -- must-gather runs `bash "$SCRIPT_SRC"`, so
          # the invocation line itself never names the script.
        | ^\s*\w+=[^=]*cnv-win-bsod-audit\.sh
        | ["']?\$\{?BSOD_CHECK_CMD\}?["']?\s
          # #4 (v0.16.0): xargs/pipe-delivered invocation, e.g.
          #   oc get vm -o name | xargs -I{} cnv-win-bsod-audit.sh {}
          # None of the alternatives above match this: the script path is
          # preceded by neither line-start, a shell metacharacter, nor
          # `bash `/`sh ` -- it is preceded by an xargs placeholder or flag
          # value, which varies too much to enumerate. `xargs` co-occurring
          # on the same line as the script name is itself the reliable
          # invocation signal (SCAN_GLOBS is already restricted to
          # executable-context files, not prose, so this cannot match a
          # runbook instruction).
        | \bxargs\b[^\n]*cnv-win-bsod-audit\.sh
        )""",
    re.VERBOSE,
)


def _strip_comment(line: str) -> str:
    out, in_single = [], False
    for ch in line:
        if ch == "'":
            in_single = not in_single
        if ch == "#" and not in_single:
            break
        out.append(ch)
    return "".join(out)


def find_invokers() -> set[str]:
    found: set[str] = set()
    for glob in SCAN_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel == SELF:
                continue
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            for raw in text.splitlines():
                if INVOKE_RE.search(_strip_comment(raw)):
                    found.add(rel)
                    break
    return found


def main() -> int:
    if not INVENTORY.is_file():
        print(f"FAIL: missing inventory {INVENTORY.relative_to(REPO_ROOT)}")
        return 1
    inv = json.loads(INVENTORY.read_text())
    declared = {c["path"]: c for c in inv["consumers"]}
    direct = {p: c for p, c in declared.items()
              if c.get("invocation", "direct") == "direct"}
    invokers = find_invokers()

    errors: list[str] = []

    # 1. Undeclared consumers.
    for path in sorted(invokers - set(declared)):
        errors.append(
            f"UNDECLARED consumer: {path}\n"
            f"      It invokes cnv-win-bsod-audit.sh but is not in "
            f"shared/audit-consumers.json.\n"
            f"      Declare it with a decides_via mode. If it acts on the exit "
            f"code and runs unattended,\n"
            f"      it MUST also pass --fail-on-unknown -- exit 0 means 'no "
            f"confirmed failures', never 'safe'."
        )

    # 2. Stale entries.
    for path in sorted(set(direct) - invokers):
        entry = declared[path]
        if not (REPO_ROOT / path).exists():
            # Layer 1/2 consumers are absent from the public GitHub tree.
            # GitLab still has the files, so they stay scanned there.
            if entry.get("export") == "internal":
                continue
            errors.append(f"STALE entry: {path} is declared but does not exist")
        else:
            errors.append(
                f"STALE entry: {path} is declared as a consumer but no longer "
                f"invokes the audit -- remove it from the inventory"
            )

    # 3. Declared requirements must actually be present in the artifact.
    for path, entry in sorted(declared.items()):
        f = REPO_ROOT / path
        if not f.is_file():
            continue
        text = f.read_text()
        for flag in entry.get("requires_flags", []):
            if flag not in text:
                errors.append(
                    f"{path}: declares it requires {flag} but the file does "
                    f"not contain it"
                )
        # The rule the whole guard exists for.
        if entry.get("unattended") and entry.get("decides_via") == "exit_code":
            if "--fail-on-unknown" not in text:
                errors.append(
                    f"{path}: UNATTENDED consumer deciding on exit_code without "
                    f"--fail-on-unknown.\n"
                    f"      An all-UNKNOWN VM exits 0, so this artifact would "
                    f"treat a VM it never assessed as passing (H2)."
                )

    print(f"Audit consumers: {len(invokers)} found, {len(declared)} declared")
    for path in sorted(invokers):
        e = declared.get(path, {})
        mode = e.get("decides_via", "?")
        tag = " [UNATTENDED]" if e.get("unattended") else ""
        print(f"  {mode:<24} {path}{tag}")

    if errors:
        print("\nFAIL: audit-consumer inventory violations:")
        for e in errors:
            print(f"  {e}")
        return 1

    print("\nOK: every audit consumer is declared, and every unattended "
          "exit-code consumer blocks on UNKNOWN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
