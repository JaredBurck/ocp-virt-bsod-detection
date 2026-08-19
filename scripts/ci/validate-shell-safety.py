#!/usr/bin/env python3
"""Reject shell-injection-prone `bash -c "..."` invocations, and the
"unsafe fetch" pattern that silently swallows `oc` failures as an empty
result (v0.16.0 Recommendation #3, the structural guard for finding #1).

H1 (v0.16.0): `must-gather/collection-scripts/gather_virt_bsod_pre` built a
nested command as a DOUBLE-quoted string with a variable interpolated by the
OUTER shell:

    bash -c "oc get virtualmachineinstancetype -n '$ns' -o json ..."

`$ns` was expanded before the inner bash ever parsed the script, so a namespace
containing a single quote escaped the `-n '...'` quoting and executed arbitrary
shell inside a privileged must-gather pod. Reproduced with
`ns="foo'; <command>; echo '"`.

The safe form -- already used by the sibling collection scripts -- passes the
value as a POSITIONAL PARAMETER, which the inner shell never re-parses as
syntax:

    bash -c 'oc get virtualmachineinstancetype -n "$1" -o json ...' _ "$ns"

This guard exists because the unsafe form was fixed in two of three sibling
files and missed in the third. Catching the *class* is the point; catching this
one instance was already done by hand.

H3 follow-up / #1 (v0.16.0): `scripts/cnv-win-bsod-audit.sh`'s per-namespace
`oc get vm`/`oc get vmi` fetches used

    VAR=$(oc get thing ... 2>/dev/null || echo '{"items":[]}')

directly, unprotected by `_oc_fetch`/`_require_evidence`. An RBAC denial or
API outage is indistinguishable from "genuinely zero items" here -- both
produce the same fallback JSON with no error signal retained anywhere, so a
namespace a caller's token could not list was silently reported as "0 VMs,
nothing to do" instead of `[UNKN]`. Four consecutive review rounds have found
a fresh instance of this exact shape in `cnv-win-bsod-audit.sh` (H3 -> H3
follow-up), so this guard closes the class structurally instead of relying on
a fifth review round to catch a fifth instance.

`_oc_fetch` (same file) is this repo's safe replacement: it always fails
closed with a parallel `<var>_ERR=1` sentinel a caller checks via
`_require_evidence` before drawing a PASS/OK conclusion from the fetch.
`_oc_fetch`'s own implementation does not use the `2>/dev/null || echo`
shape at all (it checks `$?` explicitly), so it is naturally excluded from
this pattern without needing a special-case skip.

Scope: `scripts/*.sh`, `scripts/lib/*.sh`, and `tests/*.sh` -- the gate/audit
layer that draws inline PASS/FAIL/WARN/UNKNOWN conclusions directly from a
fetch's result, per the architecture in CLAUDE.md's "Four Layers" section.
Deliberately EXCLUDES `must-gather/collection-scripts/*`: those Layer 1
collectors (`gather_virt_bsod_pre` etc.) use the same `oc get ... 2>/dev/null
|| echo '{...}'` shape extensively via `run_and_save`, but only to snapshot
best-effort data to a file for a human or the separate Layer 2
(`insights-rules/`) analysis pipeline to review later -- no inline pass/fail
verdict is drawn from the result in that file the way `cnv-win-bsod-audit.sh`
draws one per-gate. Including that layer here would flag long-standing,
architecturally-distinct, already-reviewed code with no connection to
finding #1's actual bug (a false PASS/OK verdict), not close a real gap.

Usage:
    python3 scripts/ci/validate-shell-safety.py
Exit: 0 clean, 1 violation found (either check).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

SCAN_GLOBS = (
    "scripts/*.sh",
    "scripts/lib/*.sh",
    "must-gather/collection-scripts/*",
    "tests/*.sh",
)

# Gate/audit-layer scripts only -- see the module docstring's "Scope" section
# for why must-gather/collection-scripts/* is deliberately excluded here.
UNSAFE_FETCH_SCAN_GLOBS = (
    "scripts/*.sh",
    "scripts/lib/*.sh",
    "tests/*.sh",
)

# `bash -c "` / `sh -c "` — a double-quoted inner script. Only flagged when the
# script text also contains a `$` expansion, since a constant double-quoted
# script is inert.
UNSAFE_RE = re.compile(r"\b(?:ba)?sh\s+-c\s+\"")
EXPANSION_RE = re.compile(r"\$[A-Za-z_{(]")

# An `oc get`/`oc describe` invocation whose stderr is discarded and whose
# failure falls back to an inline JSON-object/array literal via `||`. This is
# the exact shape #1 fixed: the fallback makes "the fetch failed" and "the
# fetch succeeded and found nothing" produce byte-identical output, with no
# error retained for a caller to check. Deliberately does NOT match the
# preserved single-VM fetch pattern (`|| echo ""`) -- that fallback is a
# plain empty string, not a JSON literal, and its caller already checks
# `[ -z "$VAR" ]` and emits `unknown()` explicitly (see #21's fix).
UNSAFE_FETCH_RE = re.compile(
    r"\boc\s+(?:get|describe)\b[^|]*2>(?:/dev/null|&1)\s*\|\|\s*echo\s+['\"]\{"
)


def _strip_comment(line: str) -> str:
    """Drop a trailing/whole-line comment.

    Naive but sufficient here: we only need to avoid flagging prose that
    documents the unsafe pattern (this file and gather_virt_bsod_pre both do).
    A `#` inside a string would be over-stripped, which can only cause a false
    NEGATIVE on a line that also contains `bash -c "` -- vanishingly unlikely,
    and `shellcheck` covers the surrounding syntax either way.
    """
    out = []
    in_single = False
    for ch in line:
        if ch == "'":
            in_single = not in_single
        if ch == "#" and not in_single:
            break
        out.append(ch)
    return "".join(out)


def _check_unsafe_bash_c() -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0

    for glob in SCAN_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            if not path.is_file():
                continue
            scanned += 1
            for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
                line = _strip_comment(raw)
                if UNSAFE_RE.search(line) and EXPANSION_RE.search(line):
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: "
                        f"variable-interpolating `bash -c \"...\"` -- pass the "
                        f"value positionally instead:\n"
                        f"      {raw.strip()}"
                    )

    return violations, scanned


def _check_unsafe_oc_fallback() -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0

    for glob in UNSAFE_FETCH_SCAN_GLOBS:
        for path in sorted(REPO_ROOT.glob(glob)):
            if not path.is_file():
                continue
            scanned += 1
            for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
                line = _strip_comment(raw)
                if UNSAFE_FETCH_RE.search(line):
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{lineno}: "
                        f"`oc get`/`oc describe` failure silently swallowed as "
                        f"an empty JSON result -- use _oc_fetch/_require_evidence "
                        f"instead so an RBAC denial or API outage surfaces as "
                        f"[UNKN], not a false PASS/OK:\n"
                        f"      {raw.strip()}"
                    )

    return violations, scanned


def main() -> int:
    bash_c_violations, bash_c_scanned = _check_unsafe_bash_c()
    print(f"Scanned {bash_c_scanned} shell file(s) for unsafe `bash -c \"...\"`")

    fetch_violations, fetch_scanned = _check_unsafe_oc_fallback()
    print(
        f"Scanned {fetch_scanned} gate/audit shell file(s) for unsafe "
        f"`oc get ... || echo '{{...}}'` fetch fallbacks"
    )

    ok = True

    if bash_c_violations:
        ok = False
        print("\nFAIL: shell-injection-prone command construction:")
        for v in bash_c_violations:
            print(f"  {v}")
        print(
            "\nUse the positional form the sibling collection scripts use:\n"
            "  bash -c 'oc get thing -n \"$1\" -o json' _ \"$ns\"\n"
            "The inner shell never re-parses a positional parameter as syntax, "
            "so a quote in the value cannot escape into the command."
        )
    else:
        print("OK: no variable-interpolating `bash -c \"...\"` found")

    if fetch_violations:
        ok = False
        print("\nFAIL: unsafe `oc` fetch fallback swallows failures as empty JSON:")
        for v in fetch_violations:
            print(f"  {v}")
        print(
            "\nUse _oc_fetch/_require_evidence (scripts/cnv-win-bsod-audit.sh) "
            "instead:\n"
            "  _oc_fetch VAR \"what this is\" -- get thing -n \"$ns\"\n"
            "  _require_evidence \"${VAR_ERR:-0}\" \"what this is\" || continue\n"
            "This fails closed with a `VAR_ERR=1` sentinel a caller checks "
            "before drawing a PASS/OK conclusion, instead of making a fetch "
            "failure indistinguishable from a genuinely empty result."
        )
    else:
        print("OK: no unsafe `oc` fetch fallback found")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
