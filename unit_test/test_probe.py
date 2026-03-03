import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from gato.github.probe import PermissionProber
from gato.cli import Output

Output(True, False)


def _mock_response(status_code, json_data=None):
    """Helper to create a mock HTTP response."""
    mock = MagicMock()
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
    return mock


class TestReadProbes:

    def test_contents_read_detected_on_200(self):
        api = MagicMock()
        api.call_get.return_value = _mock_response(200)
        prober = PermissionProber(api)

        perms = prober.probe_read_permissions("org/repo", is_private=True)

        assert "contents:read" in perms

    def test_contents_read_not_detected_on_403(self):
        api = MagicMock()
        api.call_get.return_value = _mock_response(403)
        prober = PermissionProber(api)

        perms = prober.probe_read_permissions("org/repo", is_private=True)

        assert "contents:read" not in perms

    def test_all_read_probes_detected(self):
        api = MagicMock()
        api.call_get.return_value = _mock_response(200)
        prober = PermissionProber(api)

        perms = prober.probe_read_permissions("org/repo", is_private=True)

        assert "contents:read" in perms
        assert "actions:read" in perms
        assert "secrets:read" in perms
        assert "administration:read" in perms

    def test_public_repo_only_probes_restricted_endpoints(self):
        api = MagicMock()
        api.call_get.return_value = _mock_response(200)
        prober = PermissionProber(api)

        perms = prober.probe_read_permissions("org/repo", is_private=False)

        assert "administration:read" in perms
        assert "secrets:read" in perms
        assert "contents:read" not in perms


class TestWriteProbes:

    def test_contents_write_detected_on_blob_201(self):
        api = MagicMock()
        api.call_post.return_value = _mock_response(201, {"sha": "abc123"})
        prober = PermissionProber(api)

        perms = {"contents:read"}
        prober.probe_write_permissions("org/repo", perms)

        assert "contents:write" in perms
        assert "contents:read" not in perms

    def test_contents_write_not_detected_on_403(self):
        api = MagicMock()
        api.call_post.return_value = _mock_response(403)
        prober = PermissionProber(api)

        perms = {"contents:read"}
        prober.probe_write_permissions("org/repo", perms)

        assert "contents:write" not in perms
        assert "contents:read" in perms

    def test_actions_write_detected_on_oidc_roundtrip(self):
        api = MagicMock()
        api.call_get.return_value = _mock_response(
            200, {"include_claim_keys": []}
        )
        api.call_put.return_value = _mock_response(204)
        prober = PermissionProber(api)

        perms = {"actions:read"}
        prober.probe_write_permissions("org/repo", perms)

        assert "actions:write" in perms


class TestDiscoverRepos:

    def test_discover_repos_returns_private_first(self):
        api = MagicMock()
        private_response = _mock_response(200, [
            {"full_name": "org/private-repo", "private": True}
        ])
        public_response = _mock_response(200, [
            {"full_name": "org/public-repo", "private": False}
        ])
        api.call_get.side_effect = [private_response, public_response]
        prober = PermissionProber(api)

        repos = prober.discover_accessible_repos()

        assert repos[0]["full_name"] == "org/private-repo"

    def test_discover_repos_empty(self):
        api = MagicMock()
        api.call_get.return_value = _mock_response(200, [])
        prober = PermissionProber(api)

        repos = prober.discover_accessible_repos()

        assert repos == []
