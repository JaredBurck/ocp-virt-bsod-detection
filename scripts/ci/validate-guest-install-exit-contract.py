#!/usr/bin/env python3
"""Validate that guest-side installers cannot report success after failing.

F-08. `install-windows-exporter.ps1` invoked msiexec as:

    Start-Process msiexec.exe -ArgumentList $installArgs -Wait -NoNewWindow

with no `-PassThru`, so the exit code was discarded. `$ErrorActionPreference =
'Stop'` does not cover this -- it governs PowerShell cmdlet errors, not a child
process's exit status -- so a failed install (1603 fatal, or 1618 "another
installation is already in progress", which Windows Update triggers routinely)
fell through to the end of the script, which exited 0.

That 0 is authoritative downstream. cnv-windows-exporter-fleet-install.sh reads
the installer's exit code as its verdict, prints "[OK] <vm>: windows_exporter
installed" and increments SUCCESS. A whole fleet could report a clean rollout
with no exporter running anywhere.

Nothing else would have surfaced it: guest CPU/memory saturation is alert-only
by design with no analyzer counterpart (see the KNOWN LIMITATION note in
alerts/bsod-risk-guest-alerts.yaml), so the only symptom is alerts that never
fire -- indistinguishable from a healthy fleet.

WHY A STATIC VALIDATOR rather than a PowerShell unit test: this is a
class-closing check, not a single-case one. Any future `Start-Process` of an
installer that drops -PassThru reintroduces the same silent success, in any
script under the scanned roots, whether or not anyone remembers to write a test
for it. It also runs in the lint stage with no pwsh image required.

Exit 0 = contract holds, 1 = violation (matches the other scripts/ci
validators).
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Roots holding scripts that run INSIDE a Windows guest. A silent failure here
# is invisible to the cluster-side layers, which is what makes it severe.
SCAN_ROOTS = ("windows-exporter", "scripts")

# Processes whose failure means "the thing we were installing is not installed".
INSTALLER_RE = re.compile(r"msiexec|setup\.exe|\.msi\b", re.IGNORECASE)

START_PROCESS_RE = re.compile(r"^(?P<indent>\s*)(?P<assign>\$\w+\s*=\s*)?Start-Process\b(?P<rest>.*)$")


def _logical_lines(text: str):
    """Yield (first_lineno, joined_text) with PowerShell backtick continuations folded.

    A multi-line `Start-Process ... `\n  -PassThru` must be seen as one
    statement, or the check reports a false violation on well-formed code.
    """
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i
        buf = lines[i]
        while buf.rstrip().endswith("`") and i + 1 < len(lines):
            buf = buf.rstrip()[:-1] + " " + lines[i + 1]
            i += 1
        yield start + 1, buf
        i += 1


def check_installer_exit_codes(errors: list) -> int:
    """Every installer Start-Process must capture and inspect its exit code."""
    checked = 0
    for root in SCAN_ROOTS:
        for ps1 in sorted((REPO / root).rglob("*.ps1")):
            text = ps1.read_text(encoding="utf-8", errors="replace")
            rel = ps1.relative_to(REPO)
            for lineno, line in _logical_lines(text):
                m = START_PROCESS_RE.match(line)
                if not m:
                    continue
                if not INSTALLER_RE.search(m.group("rest")):
                    continue
                checked += 1
                has_passthru = re.search(r"-PassThru\b", m.group("rest"), re.IGNORECASE)
                assigned = m.group("assign")
                if not has_passthru or not assigned:
                    errors.append(
                        f"{rel}:{lineno}: installer Start-Process discards its exit code. "
                        f"Use `$proc = Start-Process ... -PassThru` and act on $proc.ExitCode -- "
                        f"without it a failed install exits 0 and the fleet installer records "
                        f"the VM as a success (F-08)."
                    )
                    continue
                var = assigned.split("=")[0].strip()
                # The captured object has to actually be inspected somewhere below.
                after = text[text.find(line) if line in text else 0:]
                if not re.search(re.escape(var) + r"\.ExitCode", after):
                    errors.append(
                        f"{rel}:{lineno}: {var} captures the installer process but "
                        f"{var}.ExitCode is never inspected (F-08)."
                    )
    return checked


def check_service_verification_fails_closed(errors: list) -> int:
    """The exporter install's final service check must fail, not warn.

    A Write-Warning leaves the exit code at 0, so the fleet installer still
    counts the VM as a success -- the same silent blindness as a dropped
    msiexec exit code, one step later.
    """
    target = REPO / "windows-exporter" / "install-windows-exporter.ps1"
    if not target.exists():
        errors.append(f"{target.relative_to(REPO)}: expected file not found")
        return 0

    text = target.read_text(encoding="utf-8", errors="replace")
    idx = text.find("$svc = Get-Service")
    if idx == -1:
        errors.append(
            f"{target.relative_to(REPO)}: could not find the windows_exporter service "
            f"verification block; this validator needs updating alongside it."
        )
        return 0

    tail = text[idx:]
    if not re.search(r"Write-Error", tail):
        errors.append(
            f"{target.relative_to(REPO)}: the service verification block does not "
            f"Write-Error when windows_exporter is not running. A Write-Warning "
            f"leaves the exit code at 0, so the fleet installer records the VM as "
            f"a success with no exporter running (F-08)."
        )
    # Match `exit <non-zero>` as a statement anywhere in the block, not only on
    # a line of its own: `else { Write-Error '...'; exit 1 }` is idiomatic
    # PowerShell and satisfies the contract just as fully as the expanded form.
    # Anchoring to a whole line would reject correct code and push an author
    # toward reformatting to appease the check rather than fixing anything.
    if not re.search(r"\bexit\s+[1-9]\d*\b", tail):
        errors.append(
            f"{target.relative_to(REPO)}: the service verification block never "
            f"`exit 1`s, so a failed install is reported as success (F-08)."
        )
    return 1


def main() -> int:
    errors: list = []
    n_installers = check_installer_exit_codes(errors)
    n_service = check_service_verification_fails_closed(errors)

    if errors:
        print("FAIL: guest-install exit contract violated:\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(
        f"OK: guest-install exit contract holds -- {n_installers} installer "
        f"invocation(s) capture and inspect their exit code; "
        f"{n_service} service-verification block(s) fail closed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
