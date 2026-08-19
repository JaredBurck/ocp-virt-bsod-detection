#!/usr/bin/env python3
"""Materialize the public GitHub tree from shared/customer-export-manifest.json.

Thin wrapper around validate-customer-export.py --export, so the GitLab
publish-public-mirror job and local dry-runs share one implementation.

Usage:
    python3 scripts/ci/export-public-tree.py /tmp/public-export
Exit: 0 clean, 1 deny-scan or missing path.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_VALIDATOR = Path(__file__).resolve().parent / "validate-customer-export.py"


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: export-public-tree.py DEST", file=sys.stderr)
        return 2
    return subprocess.call(
        [sys.executable, str(_VALIDATOR), "--export", sys.argv[1]]
    )


if __name__ == "__main__":
    sys.exit(main())
