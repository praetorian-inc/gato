import pytest
from gato.models.token import TokenCapabilities


class TestTokenCapabilitiesFromClassicScopes:

    def test_repo_scope_grants_read_write_contents(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["repo"]
        )
        assert caps.can_read_contents is True
        assert caps.can_write_contents is True

    def test_repo_scope_grants_read_actions_and_secrets(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["repo"]
        )
        assert caps.can_read_actions is True
        assert caps.can_read_secrets is True

    def test_workflow_scope_grants_write_workflows_and_actions(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["workflow"]
        )
        assert caps.can_write_workflows is True
        assert caps.can_write_actions is True

    def test_admin_org_scope_grants_admin_org(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["admin:org"]
        )
        assert caps.can_admin_org is True

    def test_no_scopes_grants_nothing(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=[]
        )
        assert caps.can_read_contents is False
        assert caps.can_write_contents is False
        assert caps.can_write_workflows is False
        assert caps.can_admin_org is False

    def test_token_type_is_classic(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["repo"]
        )
        assert caps.token_type == "classic"

    def test_raw_scopes_preserved(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["repo", "workflow"]
        )
        assert caps.raw_scopes == ["repo", "workflow"]

    def test_multiple_scopes_combine(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["repo", "workflow", "admin:org"]
        )
        assert caps.can_read_contents is True
        assert caps.can_write_contents is True
        assert caps.can_write_workflows is True
        assert caps.can_write_actions is True
        assert caps.can_admin_org is True
        assert caps.can_read_secrets is True


class TestTokenCapabilitiesFromFineGrained:

    def test_contents_write_grants_read_and_write(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"contents:write"},
            expiration="2025-06-15"
        )
        assert caps.can_read_contents is True
        assert caps.can_write_contents is True

    def test_contents_read_only(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"contents:read"}
        )
        assert caps.can_read_contents is True
        assert caps.can_write_contents is False

    def test_workflows_write(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"workflows:write"}
        )
        assert caps.can_write_workflows is True

    def test_actions_read_and_write(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"actions:read", "actions:write"}
        )
        assert caps.can_read_actions is True
        assert caps.can_write_actions is True

    def test_secrets_read(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"secrets:read"}
        )
        assert caps.can_read_secrets is True

    def test_token_type_is_fine_grained(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions=set()
        )
        assert caps.token_type == "fine_grained"

    def test_expiration_stored(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions=set(),
            expiration="2025-12-31"
        )
        assert caps.expiration == "2025-12-31"

    def test_raw_scopes_are_sorted_permissions(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"contents:write", "actions:read"}
        )
        assert caps.raw_scopes == ["actions:read", "contents:write"]

    def test_full_attack_capable_token(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"contents:write", "workflows:write",
                         "actions:write", "secrets:read"}
        )
        assert caps.can_write_contents is True
        assert caps.can_write_workflows is True
        assert caps.can_write_actions is True
        assert caps.can_read_secrets is True


class TestTokenCapabilitiesDisplay:

    def test_scope_summary_classic(self):
        caps = TokenCapabilities.from_classic_scopes(
            user="testuser", name="Test User",
            scopes=["repo", "workflow"]
        )
        summary = caps.scope_summary()
        assert "repo" in summary
        assert "workflow" in summary

    def test_scope_summary_fine_grained(self):
        caps = TokenCapabilities.from_fine_grained(
            user="testuser", name="Test User",
            permissions={"contents:write", "actions:read"}
        )
        summary = caps.scope_summary()
        assert "contents:write" in summary
        assert "actions:read" in summary
