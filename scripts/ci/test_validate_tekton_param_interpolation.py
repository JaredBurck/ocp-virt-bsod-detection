"""Regression tests for scripts/ci/validate-tekton-param-interpolation.py.

Mirrors the test_validate_shared_thresholds.py / test_validate_acm_policy.py
pattern used across this CI script family: exercise the checker against a
synthetic tekton/ directory (REPO_ROOT monkeypatched to a tmp_path) with both a
vulnerable and a safe manifest, so a future refactor that silently stops
matching (e.g. a regex that no longer fires) is caught rather than turning
"fail on injection" into "always pass".
"""
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-tekton-param-interpolation.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_tekton_param_interpolation", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vtpi = _load_module()


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(vtpi, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(vtpi, "TEKTON_DIR", tmp_path / "tekton")
    (tmp_path / "tekton").mkdir()
    return tmp_path


def _write(root, name, content):
    path = root / "tekton" / name
    path.write_text(content)
    return path


VULNERABLE = """\
apiVersion: tekton.dev/v1
kind: Task
spec:
  steps:
    - name: run
      script: |
        #!/usr/bin/env bash
        /scripts/gate.sh "$(params.plan-name)" "$(params.plan-namespace)"
"""

SAFE = """\
apiVersion: tekton.dev/v1
kind: Task
spec:
  steps:
    - name: run
      env:
        - name: PLAN_NAME
          value: "$(params.plan-name)"
      script: |
        #!/usr/bin/env bash
        /scripts/gate.sh "$PLAN_NAME"
"""


class TestParamInterpolation:
    def test_params_in_script_is_flagged(self, fake_repo):
        _write(fake_repo, "task.yaml", VULNERABLE)
        assert vtpi.main() == 1

    def test_env_var_pattern_passes(self, fake_repo):
        """$(params.*) in an env: value: is the prescribed FIX, not a finding."""
        _write(fake_repo, "task.yaml", SAFE)
        assert vtpi.main() == 0

    def test_results_and_workspaces_are_not_flagged(self, fake_repo):
        """Tekton-generated paths are not PipelineRun input, so not sinks."""
        _write(fake_repo, "task.yaml", """\
apiVersion: tekton.dev/v1
kind: Task
spec:
  steps:
    - name: run
      script: |
        printf 'PASS' > "$(results.verdict.path)"
        cd "$(workspaces.source.path)"
        echo "$(context.pipelineRun.name)"
""")
        assert vtpi.main() == 0

    def test_reports_every_offending_file(self, fake_repo, capsys):
        _write(fake_repo, "task.yaml", VULNERABLE)
        _write(fake_repo, "pipeline.yaml", VULNERABLE)
        assert vtpi.main() == 1
        out = capsys.readouterr().out
        assert "task.yaml" in out and "pipeline.yaml" in out

    def test_multi_document_yaml_is_scanned(self, fake_repo):
        """Tekton manifests are commonly multi-doc; a `---` must not hide a sink."""
        _write(fake_repo, "multi.yaml", "kind: ConfigMap\n---\n" + VULNERABLE)
        assert vtpi.main() == 1

    def test_nested_step_lists_are_scanned(self, fake_repo):
        _write(fake_repo, "task.yaml", """\
apiVersion: tekton.dev/v1
kind: Task
spec:
  sidecars:
    - name: side
      script: |
        echo "$(params.message)"
""")
        assert vtpi.main() == 1

    def test_unparseable_yaml_is_flagged_not_skipped(self, fake_repo):
        """A malformed manifest must fail loudly -- silently skipping it would
        let an unscannable file carry an injection sink through CI."""
        _write(fake_repo, "broken.yaml", "spec: [unclosed\n")
        assert vtpi.main() == 1

    def test_empty_tekton_dir_passes(self, fake_repo):
        assert vtpi.main() == 0


class TestRealRepo:
    def test_shipped_tekton_manifests_are_clean(self):
        """Guards the real tekton/ tree -- this is the assertion that would
        have failed before R-04."""
        assert vtpi.main() == 0
