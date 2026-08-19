#!/usr/bin/env python3
"""Verify every local-filesystem `COPY` source in Dockerfile.gate exists.

v0.17.0 deep-dive review F2+F4: `build-gate-image` in `.gitlab-ci.yml`
previously checked a hand-copied list of paths against disk existence,
completely disconnected from what `Dockerfile.gate` actually `COPY`s. That
list had already drifted -- `Dockerfile.gate` was missing `COPY` lines for
`scripts/lib/risk-scoring.sh` and `shared/risk-scoring.json` (both required
unconditionally by `cnv-win-bsod-audit.sh`, via `scripts/lib/risk-scoring.sh`),
so the gate image failed at runtime with a `source: No such file or
directory` error, and this check passed anyway because it never looked at
the Dockerfile at all.

This script parses `Dockerfile.gate`'s own `COPY` instructions and verifies
each local source path exists, so a future added/removed `COPY` line can
never drift from the validation again. It also requires every
`/usr/share/bsod-detection/shared/*.json` path loaded by
`cnv-win-bsod-audit.sh` (and the libs it sources) to appear as a COPY
source -- existence of COPY lines is not enough if the script grew a new
JSON consumer and the image still only ships thresholds + risk-scoring.
`COPY --from=<stage>` lines reference another build stage, not the local
filesystem, and are intentionally skipped -- there is nothing on disk to
check.

Usage:
    python3 scripts/ci/validate-gate-dockerfile-copies.py [dockerfile]
Exit: 0 clean, 1 violation (missing source or unparseable COPY line).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DOCKERFILE = "Dockerfile.gate"

# Matches a single-line `COPY [--flag[=val] ...] src [src2 ...] dest`.
# Multi-line (backslash-continued) COPY instructions are out of scope --
# Dockerfile.gate does not use them, and this parser deliberately favors a
# clear failure on an unexpected form over silently mis-parsing one.
COPY_RE = re.compile(r"^\s*COPY(?:\s+(.*))?$", re.IGNORECASE)
FLAG_RE = re.compile(r"^--[\w-]+(=.*)?$")
# Container path the audit script and its sourced libs load at runtime.
# A JSON referenced here but not COPY'd is the F2/F4 class again: the image
# starts, then silently uses in-script fallbacks (weaker than a git clone).
CONTAINER_SHARED_JSON_RE = re.compile(
    r"/usr/share/bsod-detection/shared/([A-Za-z0-9._-]+\.json)"
)
AUDIT_RUNTIME_SCRIPTS = (
    "scripts/cnv-win-bsod-audit.sh",
    "scripts/lib/driver-verdict.sh",
    "scripts/lib/risk-scoring.sh",
)


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0]


def parse_copy_sources(dockerfile: Path) -> tuple[list[str], list[str]]:
    """Return (local_sources, errors) for every COPY instruction in dockerfile."""
    sources: list[str] = []
    errors: list[str] = []

    for lineno, raw in enumerate(dockerfile.read_text().splitlines(), start=1):
        line = _strip_comment(raw).rstrip()
        m = COPY_RE.match(line)
        if not m:
            continue
        if line.endswith("\\"):
            errors.append(
                f"{dockerfile.name}:{lineno}: COPY line continuation (trailing "
                f"'\\') is not supported by this parser -- rewrite as a "
                f"single-line COPY or extend validate-gate-dockerfile-copies.py"
            )
            continue
        tokens = (m.group(1) or "").split()
        if not tokens:
            errors.append(f"{dockerfile.name}:{lineno}: empty COPY instruction")
            continue
        if any(t.startswith("--from=") or t == "--from" for t in tokens):
            continue  # stage-to-stage copy -- nothing on disk to check
        args = [t for t in tokens if not FLAG_RE.match(t)]
        if len(args) < 2:
            errors.append(
                f"{dockerfile.name}:{lineno}: could not parse COPY src/dest "
                f"from: {line.strip()!r}"
            )
            continue
        # Last token is the destination; everything before it is a source.
        sources.extend(args[:-1])

    return sources, errors


def required_shared_json_from_audit_scripts() -> list[str]:
    """shared/*.json the gate image must COPY because the audit script loads them."""
    names: set[str] = set()
    for rel in AUDIT_RUNTIME_SCRIPTS:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        names.update(CONTAINER_SHARED_JSON_RE.findall(path.read_text()))
    return sorted(f"shared/{n}" for n in names)


def missing_audit_json_copies(sources: list[str]) -> list[str]:
    """Return required shared JSON paths not present in Dockerfile COPY sources."""
    copied = set(sources)
    return [req for req in required_shared_json_from_audit_scripts() if req not in copied]


def main() -> int:
    dockerfile_rel = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DOCKERFILE
    dockerfile = REPO_ROOT / dockerfile_rel
    if not dockerfile.is_file():
        print(f"FAIL: {dockerfile_rel} not found")
        return 1

    sources, errors = parse_copy_sources(dockerfile)

    print(f"Validating {dockerfile_rel} COPY sources exist "
          f"({len(sources)} local source(s) found)...")
    for src in sources:
        path = REPO_ROOT / src
        if path.is_file():
            print(f"  OK   {src}")
        else:
            errors.append(f"{src} (referenced by {dockerfile_rel} COPY) does not exist")

    for missing in missing_audit_json_copies(sources):
        errors.append(
            f"{missing} is loaded by cnv-win-bsod-audit.sh (or a lib it sources) "
            f"from /usr/share/bsod-detection/shared/ but is not COPY'd in "
            f"{dockerfile_rel}"
        )

    if errors:
        print("\nFAIL:")
        for e in errors:
            print(f"  {e}")
        return 1

    print(f"\nOK: all {len(sources)} COPY source(s) in {dockerfile_rel} exist on disk")
    return 0


if __name__ == "__main__":
    sys.exit(main())
