class TokenCapabilities:
    """Unified permission abstraction for classic PATs, fine-grained PATs,
    and GitHub App tokens.

    All downstream code checks capabilities (booleans) instead of raw scopes.
    """

    def __init__(self):
        self.can_read_contents = False
        self.can_write_contents = False
        self.can_read_actions = False
        self.can_write_actions = False
        self.can_write_workflows = False
        self.can_read_secrets = False
        self.can_admin_org = False

        self.token_type = ""
        self.user = ""
        self.name = ""
        self.expiration = None
        self.raw_scopes = []

    @classmethod
    def from_classic_scopes(cls, user: str, name: str, scopes: list):
        """Build capabilities from classic PAT OAuth scopes.

        Mapping:
            repo       -> read/write contents, read actions, read secrets
            workflow   -> write workflows, write actions
            admin:org  -> admin org
        """
        caps = cls()
        caps.token_type = "classic"
        caps.user = user
        caps.name = name
        caps.raw_scopes = list(scopes)

        if "repo" in scopes:
            caps.can_read_contents = True
            caps.can_write_contents = True
            caps.can_read_actions = True
            caps.can_read_secrets = True

        if "workflow" in scopes:
            caps.can_write_workflows = True
            caps.can_write_actions = True

        if "admin:org" in scopes:
            caps.can_admin_org = True

        return caps

    @classmethod
    def from_fine_grained(cls, user: str, name: str, permissions: set,
                          expiration: str = None):
        """Build capabilities from fine-grained PAT probed permissions.

        Mapping:
            contents:read          -> read contents
            contents:write         -> read + write contents
            actions:read           -> read actions
            actions:write          -> write actions
            workflows:write        -> write workflows
            secrets:read           -> read secrets
            administration:read    -> admin org (for org-level probes)
        """
        caps = cls()
        caps.token_type = "fine_grained"
        caps.user = user
        caps.name = name
        caps.expiration = expiration
        caps.raw_scopes = sorted(permissions)

        if "contents:read" in permissions or "contents:write" in permissions:
            caps.can_read_contents = True
        if "contents:write" in permissions:
            caps.can_write_contents = True

        if "actions:read" in permissions or "actions:write" in permissions:
            caps.can_read_actions = True
        if "actions:write" in permissions:
            caps.can_write_actions = True

        if "workflows:write" in permissions:
            caps.can_write_workflows = True

        if "secrets:read" in permissions:
            caps.can_read_secrets = True

        if "administration:read" in permissions:
            caps.can_admin_org = True

        return caps

    @classmethod
    def for_app_token(cls):
        """Build minimal capabilities for GitHub App tokens."""
        caps = cls()
        caps.token_type = "app"
        caps.user = "Github App"
        caps.name = "GATO App Mode"
        caps.raw_scopes = []
        return caps

    def scope_summary(self) -> str:
        """Human-readable string of raw scopes/permissions for display."""
        return ", ".join(self.raw_scopes) if self.raw_scopes else "(none)"
