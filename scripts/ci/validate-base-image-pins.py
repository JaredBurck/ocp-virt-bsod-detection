#!/usr/bin/env python3
"""Verify every pinned base-image digest is still pullable, and flag floating tags.

M2 (v0.16.0), reversed for `pg-must-gather` post-Phase 6. Two distinct
problems, deliberately treated differently:

1. The upstream `pg-must-gather` development image (Quay `pg.next` project) is published
   as `:latest` only, rebuilt often, and its old digests ARE garbage-collected
   -- observed as fast as 2 days between a pin and it going dead. M2
   originally pinned this by digest; that pin was removed from
   `must-gather/Dockerfile` once the trade-off was re-examined: the artifact
   that actually needs to be reproducible for a support case is the BSOD
   framework version (git tag + `TOOL_VERSION`), not this upstream harness,
   which the Dockerfile renames out of the way immediately. This image is no
   longer pinned or tracked here on purpose -- `VOLATILE_PREFIXES` below
   exists only as a defensive fallback in case a future pin of this same
   registry reappears in any scanned file.

2. `registry.redhat.io/*` and `registry.access.redhat.com/*` are Red Hat
   *product* registries: stable and long-lived (ose-cli:latest resolved to an
   image ~10 months old when pinned). Those are pinned by digest with no
   mirroring needed, and this script fails if any float back to a tag.

Requires `skopeo`. Skips the reachability check when unauthenticated or offline
so the guard never produces a false failure in a sandboxed runner -- but the
floating-tag check always runs, since it needs no network.

Usage:
    python3 scripts/ci/validate-base-image-pins.py
Exit: 0 clean (or skipped), 1 violation.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

SCAN = ("Dockerfile.gate", "Dockerfile.gate-exporter", "must-gather/Dockerfile",
        "tekton/bsod-gate-pipeline.yaml", "tekton/bsod-gate-task.yaml",
        "tekton/bsod-gate-prehook-job.yaml", "dashboards/grafana-5.24.0.yaml")

PINNED_RE = re.compile(r"(?:FROM|image:)\s+([\w./-]+)@(sha256:[a-f0-9]{64})")
# A floating tag on a Red Hat registry. Our own quay.io/jburck images are
# release-tagged (v0.16.0) and governed by validate-doc-counts.py instead.
FLOATING_RE = re.compile(r"(?:FROM|image:)\s+((?:registry\.redhat\.io|registry\.access\.redhat\.com)[\w./-]+):(\w[\w.-]*)")

# Registries whose digests are known to be garbage-collected. A dead pin here
# is expected eventually and is reported as an actionable refresh, not a bug.
VOLATILE_PREFIXES = ("quay.io/pg.next/",)


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0]


# N18 (v0.16.0 #18): pulled out into its own function so a regression in the
# soft-skip classification (e.g. losing the 403/forbidden case again) has a
# direct unit test instead of only being reachable through a live skopeo call.
def _is_soft_skip_error(err: str) -> bool:
    """True if `err` looks like 'we could not verify this from here'
    (unauthenticated/under-scoped), not a genuine unreachable-digest finding.

    Some registries return 403 Forbidden (not 401 Unauthorized) for an
    unauthenticated or under-scoped pull -- treating only "unauthorized"/
    "authentication" as soft-skip conditions missed that real-world case.
    """
    err_lower = err.lower()
    return ("unauthorized" in err_lower or "authentication" in err_lower
            or "403" in err_lower or "forbidden" in err_lower)


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    pins: list[tuple[str, str, str]] = []

    for rel in SCAN:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
            line = _strip_comment(raw)
            for m in PINNED_RE.finditer(line):
                pins.append((rel, m.group(1), m.group(2)))
            for m in FLOATING_RE.finditer(line):
                errors.append(
                    f"{rel}:{lineno}: Red Hat product image floats on "
                    f"':{m.group(2)}' -- pin by digest:\n"
                    f"      skopeo inspect docker://{m.group(1)}:{m.group(2)} "
                    f"--format '{{{{.Digest}}}}'"
                )

    print(f"Found {len(pins)} digest-pinned base image(s); "
          f"{len(errors)} floating Red Hat tag(s)")

    if shutil.which("skopeo") is None:
        print("SKIP: skopeo not installed -- digest reachability not verified")
    else:
        for rel, repo, digest in pins:
            ref = f"docker://{repo}@{digest}"
            try:
                r = subprocess.run(["skopeo", "inspect", ref, "--format", "{{.Digest}}"],
                                   capture_output=True, text=True, timeout=120)
            except subprocess.TimeoutExpired:
                warnings.append(f"{rel}: timed out inspecting {repo} -- not verified")
                continue
            if r.returncode == 0:
                print(f"  OK   {repo}@{digest[:19]}...")
                continue
            err = (r.stderr or "").strip().splitlines()[-1] if r.stderr else "unknown"
            if _is_soft_skip_error(err):
                warnings.append(f"{rel}: not authenticated for {repo} -- skipped ({err})")
            elif any(repo.startswith(p) for p in VOLATILE_PREFIXES):
                errors.append(
                    f"{rel}: pinned digest for {repo} is NO LONGER PULLABLE.\n"
                    f"      {err}\n"
                    f"      This registry garbage-collects digests; refresh the pin:\n"
                    f"        skopeo inspect docker://{repo}:latest --format '{{{{.Digest}}}}'\n"
                    f"      (Expected periodically -- see the accepted-risk note in "
                    f"must-gather/Dockerfile.)"
                )
            else:
                errors.append(f"{rel}: {repo}@{digest[:19]}... unreachable: {err}")

    for w in warnings:
        print(f"  WARN {w}")

    if errors:
        print("\nFAIL: base-image pin problems:")
        for e in errors:
            print(f"  {e}")
        return 1

    print("\nOK: all pinned digests reachable (or skipped); no floating Red Hat tags")
    return 0


if __name__ == "__main__":
    sys.exit(main())
