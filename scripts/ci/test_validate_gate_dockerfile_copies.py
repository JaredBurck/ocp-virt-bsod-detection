"""Regression tests for scripts/ci/validate-gate-dockerfile-copies.py.

v0.17.0 deep-dive review F2+F4: `build-gate-image`'s COPY-source check used to
be a hand-copied list disconnected from `Dockerfile.gate` itself, and that
list had already drifted (missing risk-scoring.sh/.json), letting a runtime
`source: No such file or directory` failure ship undetected. These tests pin
the parser's behavior directly against synthetic Dockerfiles so a future
regression in the parsing logic (not just the file list) is caught too.
"""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-gate-dockerfile-copies.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_gate_dockerfile_copies", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vgdc = _load_module()


def _write(tmp_path, content):
    dockerfile = tmp_path / "Dockerfile.test"
    dockerfile.write_text(content)
    return dockerfile


class TestParseCopySources:
    def test_simple_copy_extracted(self, tmp_path):
        dockerfile = _write(tmp_path, "FROM scratch\nCOPY foo.sh /scripts/foo.sh\n")
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == ["foo.sh"]
        assert errors == []

    def test_multiple_copy_lines(self, tmp_path):
        dockerfile = _write(
            tmp_path,
            "FROM scratch\n"
            "COPY a.sh /scripts/a.sh\n"
            "COPY shared/b.json /usr/share/bsod-detection/shared/b.json\n",
        )
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == ["a.sh", "shared/b.json"]
        assert errors == []

    def test_from_stage_copy_is_skipped(self, tmp_path):
        """COPY --from=<stage> references another build stage, not the local
        filesystem -- there is nothing on disk to check, and treating the
        stage-relative path as a repo-relative path would be a false FAIL."""
        dockerfile = _write(
            tmp_path,
            "FROM builder AS b\nCOPY --from=b /usr/bin/oc /usr/bin/oc\n",
        )
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == []
        assert errors == []

    def test_multiple_sources_one_dest(self, tmp_path):
        dockerfile = _write(tmp_path, "FROM scratch\nCOPY a.sh b.sh /scripts/\n")
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == ["a.sh", "b.sh"]
        assert errors == []

    def test_comment_only_line_ignored(self, tmp_path):
        dockerfile = _write(tmp_path, "FROM scratch\n# COPY commented.sh /x\n")
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == []
        assert errors == []

    def test_trailing_comment_stripped(self, tmp_path):
        dockerfile = _write(tmp_path, "FROM scratch\nCOPY a.sh /scripts/a.sh  # note\n")
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == ["a.sh"]
        assert errors == []

    def test_line_continuation_flagged_as_error(self, tmp_path):
        """A backslash-continued COPY is out of this parser's supported
        grammar -- it must be reported as an explicit error, not silently
        mis-parsed into a wrong (and possibly falsely-passing) source list."""
        dockerfile = _write(tmp_path, "FROM scratch\nCOPY a.sh \\\n    /scripts/a.sh\n")
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == []
        assert len(errors) == 1
        assert "line continuation" in errors[0]

    def test_unrelated_backslash_continuation_not_flagged(self, tmp_path):
        """Only COPY lines are subject to the continuation restriction --
        RUN/LABEL line continuations elsewhere in the file (the common case
        in this repo's actual Dockerfile.gate) must not false-positive."""
        dockerfile = _write(
            tmp_path,
            "FROM scratch\n"
            "RUN echo hi \\\n"
            "    && echo bye\n"
            "COPY a.sh /scripts/a.sh\n",
        )
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == ["a.sh"]
        assert errors == []

    def test_empty_copy_instruction_is_error(self, tmp_path):
        dockerfile = _write(tmp_path, "FROM scratch\nCOPY\n")
        sources, errors = vgdc.parse_copy_sources(dockerfile)
        assert sources == []
        assert len(errors) == 1


class TestMainIntegration:
    def test_missing_source_fails(self, tmp_path, monkeypatch, capsys):
        dockerfile = _write(tmp_path, "FROM scratch\nCOPY does/not/exist.sh /x\n")
        monkeypatch.setattr(vgdc, "REPO_ROOT", tmp_path)
        monkeypatch.setattr("sys.argv", ["validate-gate-dockerfile-copies.py", dockerfile.name])
        assert vgdc.main() == 1
        assert "does not exist" in capsys.readouterr().out

    def test_existing_source_passes(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "present.sh").write_text("#!/bin/bash\n")
        dockerfile = _write(tmp_path, "FROM scratch\nCOPY present.sh /x\n")
        monkeypatch.setattr(vgdc, "REPO_ROOT", tmp_path)
        monkeypatch.setattr("sys.argv", ["validate-gate-dockerfile-copies.py", dockerfile.name])
        assert vgdc.main() == 0
        assert "OK: all 1 COPY source(s)" in capsys.readouterr().out

    def test_real_dockerfile_gate_passes(self, monkeypatch):
        """Integration check against the actual repo file -- this is the
        exact regression F2/F4 targets: a missing COPY source must fail here,
        not just in the synthetic fixtures above.

        sys.argv must be pinned: main() reads sys.argv[1] as the Dockerfile
        path, and under pytest that is pytest's OWN argument. Without this the
        test's result depended on how pytest was invoked -- it passed under
        `pytest <file>` (argv[1] happened to be a readable file, which parses
        to zero COPY lines and trivially returns 0) but failed under
        `pytest scripts/ci/` (argv[1] is a directory -> "not found" -> 1). The
        sibling test above already pinned argv; this one was missed.
        """
        monkeypatch.setattr("sys.argv", ["validate-gate-dockerfile-copies.py"])
        assert vgdc.main() == 0

    def test_real_dockerfile_gate_exporter_passes(self, monkeypatch):
        """Same integration guard as test_real_dockerfile_gate_passes, for
        Issue K / R-27's exporter image (Dockerfile.gate-exporter)."""
        monkeypatch.setattr(
            "sys.argv",
            ["validate-gate-dockerfile-copies.py", "Dockerfile.gate-exporter"])
        assert vgdc.main() == 0


class TestAuditScriptJsonMustBeCopied:
    def test_missing_guest_os_and_baseline_are_reported(self):
        """The previous COPY-existence-only check passed while the audit
        script loaded virtio-win-guest-os-support.json and
        template-baseline.json from the container path -- those files were
        never COPY'd, so the image silently used in-script fallbacks."""
        missing = vgdc.missing_audit_json_copies(
            [
                "shared/virtio-win-thresholds.json",
                "shared/risk-scoring.json",
            ]
        )
        assert "shared/virtio-win-guest-os-support.json" in missing
        assert "shared/template-baseline.json" in missing

    def test_complete_copy_list_is_clean(self):
        required = vgdc.required_shared_json_from_audit_scripts()
        assert vgdc.missing_audit_json_copies(required) == []
        assert "shared/virtio-win-thresholds.json" in required
        assert "shared/risk-scoring.json" in required
        assert "shared/virtio-win-guest-os-support.json" in required
        assert "shared/template-baseline.json" in required
