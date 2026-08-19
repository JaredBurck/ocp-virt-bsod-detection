"""Regression tests for scripts/ci/validate-base-image-pins.py.

N18 (v0.16.0 #18): the soft-skip classification for an unreachable pinned
digest previously recognized only "unauthorized"/"authentication" substrings
in skopeo's stderr as "we could not verify this, don't fail the build" --
missing the real-world case of a registry returning 403 Forbidden (not 401
Unauthorized) for an unauthenticated or under-scoped pull. These tests pin
the classification function's behavior directly, following the same
importlib-load pattern test_validate_shared_thresholds.py already uses for
this CI script family (the module filename has a hyphen and isn't a normal
importable package).
"""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "validate-base-image-pins.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_base_image_pins", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vbip = _load_module()


class TestIsSoftSkipError:
    def test_unauthorized_is_soft_skip(self):
        assert vbip._is_soft_skip_error("Error: unauthorized: authentication required")

    def test_authentication_required_is_soft_skip(self):
        assert vbip._is_soft_skip_error("received unexpected HTTP status: 401 authentication required")

    def test_403_status_code_is_soft_skip(self):
        """N18: some registries return a bare 403 with no 'unauthorized'/
        'authentication' substring at all for an under-scoped pull."""
        assert vbip._is_soft_skip_error("received unexpected HTTP status: 403 Forbidden")

    def test_forbidden_word_is_soft_skip(self):
        assert vbip._is_soft_skip_error("Error: reading manifest: forbidden")

    def test_case_insensitive(self):
        assert vbip._is_soft_skip_error("ERROR: 403 FORBIDDEN")

    def test_genuine_not_found_is_not_soft_skip(self):
        """A real 'digest garbage-collected' failure must still be reported
        as an error, not silently downgraded to a warning."""
        assert not vbip._is_soft_skip_error("manifest unknown: manifest unknown")

    def test_generic_network_error_is_not_soft_skip(self):
        assert not vbip._is_soft_skip_error("dial tcp: lookup registry.redhat.io: no such host")

    def test_timeout_message_is_not_soft_skip(self):
        assert not vbip._is_soft_skip_error("context deadline exceeded")


class TestVolatilePrefixHandling:
    """Sanity-check the constant used to distinguish 'expected to eventually
    be unpullable' (quay.io/pg.next) from 'should never be unpullable'
    (registry.redhat.io) -- unrelated to #18 but exercised by the same
    integration path in main(), and previously had zero test coverage."""

    def test_pg_next_is_volatile(self):
        assert any("quay.io/pg.next/".startswith(p) or "quay.io/pg.next/foo".startswith(p)
                   for p in vbip.VOLATILE_PREFIXES)

    def test_registry_redhat_io_is_not_volatile(self):
        assert not any("registry.redhat.io/ubi9".startswith(p) for p in vbip.VOLATILE_PREFIXES)
