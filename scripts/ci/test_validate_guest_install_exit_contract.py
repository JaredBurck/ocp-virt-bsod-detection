"""Regression tests for scripts/ci/validate-guest-install-exit-contract.py.

Peer-review finding F-08: install-windows-exporter.ps1 ran msiexec through
`Start-Process ... -Wait -NoNewWindow` with no `-PassThru`, so the exit code
was discarded, and its final service check only emitted a Write-Warning. A
failed install therefore exited 0, and cnv-windows-exporter-fleet-install.sh --
which reads that exit code as the installer's verdict -- printed
"[OK] <vm>: windows_exporter installed" and counted it a success.

Nothing downstream could contradict it: guest CPU/memory saturation is
alert-only by design with no analyzer counterpart, so the only symptom of a
fleet-wide failed rollout is alerts that never fire, which looks exactly like a
healthy fleet.

These tests pin the validator that closes the class. The important property is
NOT that it accepts the current tree -- that is one assertion -- but that it
still rejects each shape the bug can take: no -PassThru, -PassThru captured but
never inspected, and a service check that warns instead of failing. A validator
that only recognised the exact pre-fix spelling would let the next variant
through, which is the failure mode CLAUDE.md's Design Rule 2 exists to prevent.
"""
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-guest-install-exit-contract.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_guest_install_exit_contract", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


val = _load_module()


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """A minimal tree with the two scanned roots, rooted at tmp_path."""
    (tmp_path / "windows-exporter").mkdir()
    (tmp_path / "scripts").mkdir()
    monkeypatch.setattr(val, "REPO", tmp_path)
    return tmp_path


def _write_installer(repo, msi_line, service_block):
    (repo / "windows-exporter" / "install-windows-exporter.ps1").write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"{msi_line}\n"
        "Start-Sleep -Seconds 3\n"
        "$svc = Get-Service -Name 'windows_exporter' -ErrorAction SilentlyContinue\n"
        f"{service_block}\n",
        encoding="utf-8",
    )


GOOD_MSI = (
    "$msiProc = Start-Process msiexec.exe -ArgumentList $installArgs "
    "-Wait -NoNewWindow -PassThru\n"
    "if ($msiProc.ExitCode -ne 0) { Write-Error 'boom'; exit 1 }"
)
GOOD_SERVICE = (
    "if ($svc -and $svc.Status -eq 'Running') { Write-Host 'ok' }\n"
    "else { Write-Error 'not running'; exit 1 }"
)


class TestInstallerExitCode:
    """The msiexec half: a discarded exit code is the original F-08 defect."""

    def test_accepts_passthru_with_inspected_exitcode(self, fake_repo):
        _write_installer(fake_repo, GOOD_MSI, GOOD_SERVICE)
        errors = []
        assert val.check_installer_exit_codes(errors) == 1
        assert errors == []

    def test_rejects_missing_passthru(self, fake_repo):
        """The exact pre-fix shape."""
        _write_installer(
            fake_repo,
            "Start-Process msiexec.exe -ArgumentList $installArgs -Wait -NoNewWindow",
            GOOD_SERVICE,
        )
        errors = []
        val.check_installer_exit_codes(errors)
        assert len(errors) == 1
        assert "discards its exit code" in errors[0]

    def test_rejects_passthru_never_inspected(self, fake_repo):
        """A subtler variant: captured, then ignored.

        -PassThru alone changes nothing if no one reads .ExitCode -- the
        install still fails silently. A validator that only grepped for
        '-PassThru' would call this fixed.
        """
        _write_installer(
            fake_repo,
            "$p = Start-Process msiexec.exe -ArgumentList $a -Wait -PassThru",
            GOOD_SERVICE,
        )
        errors = []
        val.check_installer_exit_codes(errors)
        assert len(errors) == 1
        assert "never inspected" in errors[0]

    def test_folds_backtick_continuations(self, fake_repo):
        """PowerShell line continuations must not read as a truncated statement.

        Splitting -PassThru onto its own continued line is idiomatic and must
        not be reported as a violation.
        """
        _write_installer(
            fake_repo,
            "$msiProc = Start-Process msiexec.exe `\n"
            "  -ArgumentList $installArgs -Wait -NoNewWindow -PassThru\n"
            "if ($msiProc.ExitCode -ne 0) { exit 1 }",
            GOOD_SERVICE,
        )
        errors = []
        val.check_installer_exit_codes(errors)
        assert errors == []

    def test_ignores_non_installer_start_process(self, fake_repo):
        """Scope guard: only installers carry this contract.

        Over-broad matching would force -PassThru onto every Start-Process in
        the repo and get the check disabled rather than fixed.
        """
        _write_installer(fake_repo, GOOD_MSI, GOOD_SERVICE)
        (fake_repo / "scripts" / "helper.ps1").write_text(
            "Start-Process notepad.exe -Wait -NoNewWindow\n", encoding="utf-8")
        errors = []
        assert val.check_installer_exit_codes(errors) == 1  # notepad not counted
        assert errors == []


class TestServiceVerification:
    """The second half: warning about a dead service still exits 0."""

    def test_accepts_failing_closed(self, fake_repo):
        _write_installer(fake_repo, GOOD_MSI, GOOD_SERVICE)
        errors = []
        val.check_service_verification_fails_closed(errors)
        assert errors == []

    def test_rejects_write_warning_only(self, fake_repo):
        """The exact pre-fix shape: a warning leaves the exit code at 0."""
        _write_installer(
            fake_repo,
            GOOD_MSI,
            "if ($svc -and $svc.Status -eq 'Running') { Write-Host 'ok' }\n"
            "else { Write-Warning 'not detected as running.' }",
        )
        errors = []
        val.check_service_verification_fails_closed(errors)
        assert len(errors) == 2  # no Write-Error, and no exit 1
        assert any("Write-Error" in e for e in errors)
        assert any("exit 1" in e for e in errors)

    def test_reports_when_block_cannot_be_found(self, fake_repo):
        """Fail loudly rather than silently passing on an unrecognised file.

        If the service check is renamed or restructured, this validator must
        say so -- silently finding nothing to check is how a guard rots into a
        no-op that still prints OK.
        """
        (fake_repo / "windows-exporter" / "install-windows-exporter.ps1").write_text(
            "Write-Host 'restructured'\n", encoding="utf-8")
        errors = []
        val.check_service_verification_fails_closed(errors)
        assert len(errors) == 1
        assert "could not find" in errors[0]


class TestRealTree:
    """The shipped tree must satisfy the contract."""

    def test_repository_passes(self):
        assert val.main() == 0
