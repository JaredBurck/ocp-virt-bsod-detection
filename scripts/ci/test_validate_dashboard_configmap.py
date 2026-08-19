"""Regression tests for scripts/ci/validate-dashboard-configmap.py.

Peer-review v0.7.0 item 24: the "VirtIO Driver Versions by VM" panel queried
bsod_virtio_driver_version (a windows_exporter metric whose VM identity is
added via ServiceMonitor relabeling as vm_name/vm_namespace -- see
windows-exporter/servicemonitor-windows-vms.yaml) but its Grafana table
"organize" transformation indexed/renamed columns by "name"/"namespace"
instead, which don't exist on that series -- the VM/Namespace columns
rendered blank. check_windows_exporter_panels_use_vm_name_label() guards
against this class of bug recurring on this or any future windows_exporter
table panel.
"""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-dashboard-configmap.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_dashboard_configmap", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vdc = _load_module()


def _panel_with_organize_transform(expr, index_by_name, rename_by_name):
    return {
        "title": "Test Panel",
        "targets": [{"expr": expr}],
        "transformations": [
            {
                "id": "organize",
                "options": {
                    "indexByName": index_by_name,
                    "renameByName": rename_by_name,
                },
            }
        ],
    }


class TestCheckWindowsExporterPanelsUseVmNameLabel:
    def test_correct_vm_name_columns_pass(self):
        dashboard = {"panels": [_panel_with_organize_transform(
            "bsod_virtio_driver_version == 1",
            {"vm_name": 0, "vm_namespace": 1, "version": 2},
            {"vm_name": "VM", "vm_namespace": "Namespace", "version": "VirtIO Driver Version"},
        )]}
        assert vdc.check_windows_exporter_panels_use_vm_name_label(dashboard) == 0

    def test_bare_name_namespace_columns_fail(self):
        """Reproduces the exact pre-fix bug."""
        dashboard = {"panels": [_panel_with_organize_transform(
            "bsod_virtio_driver_version == 1",
            {"name": 0, "namespace": 1, "version": 2},
            {"name": "VM", "namespace": "Namespace", "version": "VirtIO Driver Version"},
        )]}
        assert vdc.check_windows_exporter_panels_use_vm_name_label(dashboard) == 1

    def test_name_namespace_ok_for_non_windows_exporter_panel(self):
        """kubevirt_vmi_info / ALERTS-sourced panels legitimately use
        name/namespace (the native KubeVirt VM identity labels) -- only
        windows_exporter (bsod_*/windows_*) series lack them."""
        dashboard = {"panels": [_panel_with_organize_transform(
            "count by (name, namespace) (ALERTS{alertname=~\"BSODRisk_.*\"})",
            {"name": 0, "namespace": 1},
            {"name": "VM", "namespace": "Namespace"},
        )]}
        assert vdc.check_windows_exporter_panels_use_vm_name_label(dashboard) == 0

    def test_panel_with_no_organize_transform_is_ignored(self):
        dashboard = {"panels": [{
            "title": "Graph Panel",
            "targets": [{"expr": "bsod_virtio_package_version"}],
            "transformations": [],
        }]}
        assert vdc.check_windows_exporter_panels_use_vm_name_label(dashboard) == 0

    def test_real_dashboard_json_passes(self):
        """Guards against the committed dashboard regressing."""
        standalone = vdc._load_standalone()
        assert vdc.check_windows_exporter_panels_use_vm_name_label(standalone) == 0


def _stat_panel(panel_id, title, expr="up", ds_uid="${datasource}", targets=None):
    panel = {
        "id": panel_id,
        "title": title,
        "type": "stat",
        "datasource": {"type": "prometheus", "uid": ds_uid},
    }
    panel["targets"] = [{"expr": expr, "refId": "A"}] if targets is None else targets
    return panel


def _row_panel(panel_id, title):
    """`row` panels are structural dividers -- Grafana gives them no
    datasource/targets of their own."""
    return {"id": panel_id, "title": title, "type": "row"}


class TestCheckPanelStructure:
    def test_clean_dashboard_passes(self):
        dashboard = {"panels": [
            _row_panel(100, "Section"),
            _stat_panel(1, "Panel A", expr="up"),
            _stat_panel(2, "Panel B", expr="down"),
        ]}
        assert vdc.check_panel_structure("test", dashboard) == 0

    def test_duplicate_title_fails(self):
        dashboard = {"panels": [
            _stat_panel(1, "Same Title"),
            _stat_panel(2, "Same Title"),
        ]}
        assert vdc.check_panel_structure("test", dashboard) == 1

    def test_row_panel_title_collision_with_real_panel_fails(self):
        """Title uniqueness applies across row dividers too -- a row titled
        the same as a real panel is confusing either way, even though rows
        are exempt from the datasource/targets checks below."""
        dashboard = {"panels": [
            _row_panel(100, "Same Title"),
            _stat_panel(1, "Same Title"),
        ]}
        assert vdc.check_panel_structure("test", dashboard) == 1

    def test_empty_targets_list_fails(self):
        dashboard = {"panels": [_stat_panel(1, "Panel A", targets=[])]}
        assert vdc.check_panel_structure("test", dashboard) == 1

    def test_empty_expr_fails(self):
        dashboard = {"panels": [_stat_panel(1, "Panel A", expr="")]}
        assert vdc.check_panel_structure("test", dashboard) == 1

    def test_whitespace_only_expr_fails(self):
        dashboard = {"panels": [_stat_panel(1, "Panel A", expr="   ")]}
        assert vdc.check_panel_structure("test", dashboard) == 1

    def test_missing_expr_key_fails(self):
        dashboard = {"panels": [_stat_panel(1, "Panel A", targets=[{"refId": "A"}])]}
        assert vdc.check_panel_structure("test", dashboard) == 1

    def test_mismatched_datasource_fails(self):
        """A hardcoded uid left over from a panel-picker export, instead of
        the ${datasource} template variable every other panel uses."""
        dashboard = {"panels": [
            _stat_panel(1, "Panel A", ds_uid="${datasource}"),
            _stat_panel(2, "Panel B", ds_uid="hardcoded-uid-abc123"),
        ]}
        assert vdc.check_panel_structure("test", dashboard) == 1

    def test_row_panels_exempt_from_datasource_check(self):
        """A row panel's missing datasource must not be counted as a second
        distinct datasource -- it legitimately has none."""
        dashboard = {"panels": [
            _row_panel(100, "Section"),
            _stat_panel(1, "Panel A"),
            _stat_panel(2, "Panel B"),
        ]}
        assert vdc.check_panel_structure("test", dashboard) == 0

    def test_real_dashboard_json_passes(self):
        """Guards against the committed dashboards regressing."""
        standalone = vdc._load_standalone()
        assert vdc.check_panel_structure(vdc.STANDALONE_PATH, standalone) == 0

    def test_real_fleet_dashboard_json_passes(self):
        import json
        fleet = json.load(open(vdc.FLEET_STANDALONE_PATH))
        assert vdc.check_panel_structure(vdc.FLEET_STANDALONE_PATH, fleet) == 0
