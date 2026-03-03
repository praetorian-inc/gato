# Fine-Grained PAT Support — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add fine-grained PAT support to Gato via a unified `TokenCapabilities` abstraction that normalizes classic scopes and fine-grained permissions, including probe-based permission discovery and full attack support.

**Architecture:** New `TokenCapabilities` class in `gato/models/token.py` maps both classic OAuth scopes and fine-grained probe results to unified boolean capabilities. New `PermissionProber` in `gato/github/probe.py` discovers FG PAT permissions by testing endpoints. All 12+ downstream scope-check sites are refactored to use capabilities instead of string matching.

**Tech Stack:** Python 3.7+, pytest, unittest.mock, requests (existing)

---

### Task 1: Create TokenCapabilities Model

**Files:**
- Create: `gato/models/token.py`
- Modify: `gato/models/__init__.py`
- Test: `unit_test/test_token.py`

**Step 1: Write failing tests for TokenCapabilities**

Create `unit_test/test_token.py`:

```python
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_token.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gato.models.token'`

**Step 3: Implement TokenCapabilities**

Create `gato/models/token.py`:

```python
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
```

**Step 4: Update `gato/models/__init__.py` to export TokenCapabilities**

Add this import to the existing file:

```python
from .token import TokenCapabilities
```

So it becomes:
```python
from .repository import Repository
from .organization import Organization
from .execution import Execution
from .secret import Secret
from .runner import Runner
from .token import TokenCapabilities
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_token.py -v`
Expected: All PASS

**Step 6: Commit**

```bash
git add gato/models/token.py gato/models/__init__.py unit_test/test_token.py
git commit -m "feat: add TokenCapabilities unified permission model"
```

---

### Task 2: Create Permission Probing Engine

**Files:**
- Create: `gato/github/probe.py`
- Test: `unit_test/test_probe.py`

**Step 1: Write failing tests for PermissionProber**

Create `unit_test/test_probe.py`:

```python
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

        # Public repos: contents/actions/issues/pulls always succeed,
        # so we only probe administration, secrets, variables
        assert "administration:read" in perms
        assert "secrets:read" in perms
        # contents:read should NOT be in results for public
        # (it's always true for public, so not probed)
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
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_probe.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gato.github.probe'`

**Step 3: Implement PermissionProber**

Create `gato/github/probe.py`:

```python
import logging

from gato.cli import Output

logger = logging.getLogger(__name__)


class PermissionProber:
    """Discovers fine-grained PAT permissions by probing API endpoints.

    Probes are designed to be no-ops — they don't create visible artifacts.
    Read probes use GET requests. Write probes use minimal POST/PUT that
    produce only dangling/unreferenced objects.
    """

    # Endpoints to probe for read permissions on private repos.
    # Public repos return 200 for most read endpoints regardless of
    # token permissions, so we only probe restricted endpoints for public.
    PRIVATE_READ_PROBES = {
        "contents:read": "/repos/{repo}/commits",
        "actions:read": "/repos/{repo}/actions/workflows",
        "secrets:read": "/repos/{repo}/actions/secrets",
        "administration:read": "/repos/{repo}/actions/permissions",
    }

    PUBLIC_READ_PROBES = {
        "administration:read": "/repos/{repo}/actions/permissions",
        "secrets:read": "/repos/{repo}/actions/secrets",
    }

    def __init__(self, api):
        """Initialize the prober with an existing Api instance.

        Args:
            api: Instantiated gato.github.Api object.
        """
        self.api = api

    def discover_accessible_repos(self) -> list:
        """Discover repositories accessible to the fine-grained PAT.

        Returns private repos first (better for probing since public
        repos have looser permission checks).

        Returns:
            list: Combined list of repo dicts, private first.
        """
        all_repos = []
        for visibility in ["private", "public"]:
            result = self.api.call_get(
                "/user/repos",
                params={
                    "affiliation": "owner,collaborator,organization_member",
                    "visibility": visibility,
                    "per_page": 100,
                }
            )
            if result.status_code == 200:
                all_repos.extend(result.json())

        return all_repos

    def probe_read_permissions(self, repo: str,
                               is_private: bool = True) -> set:
        """Probe GET endpoints to detect read permissions.

        Args:
            repo: Repository in org/repo format.
            is_private: Whether the repo is private (determines probe set).

        Returns:
            set: Detected permission strings (e.g. {"contents:read"}).
        """
        probes = (self.PRIVATE_READ_PROBES if is_private
                  else self.PUBLIC_READ_PROBES)
        detected = set()

        for permission, endpoint_template in probes.items():
            endpoint = endpoint_template.format(repo=repo)
            try:
                result = self.api.call_get(endpoint)
                if result.status_code == 200:
                    detected.add(permission)
            except Exception as e:
                logger.debug(f"Read probe {permission} error: {e}")

        return detected

    def probe_write_permissions(self, repo: str, permissions: set) -> None:
        """Probe write access for detected read permissions. Mutates the
        permissions set in-place — upgrades read to write where detected.

        Args:
            repo: Repository in org/repo format.
            permissions: Set of detected permissions (mutated in-place).
        """
        # Contents write: create a dangling blob (unreferenced, invisible)
        if "contents:read" in permissions:
            try:
                result = self.api.call_post(
                    f"/repos/{repo}/git/blobs",
                    params={"content": "probe", "encoding": "utf-8"}
                )
                if result.status_code == 201:
                    permissions.discard("contents:read")
                    permissions.add("contents:write")
            except Exception as e:
                logger.debug(f"Contents write probe error: {e}")

        # Actions write: read OIDC settings and re-set same value
        if "actions:read" in permissions:
            try:
                oidc_result = self.api.call_get(
                    f"/repos/{repo}/actions/oidc/customization/sub"
                )
                if oidc_result.status_code == 200:
                    current = oidc_result.json()
                    set_result = self.api.call_put(
                        f"/repos/{repo}/actions/oidc/customization/sub",
                        params=current
                    )
                    if set_result.status_code in [201, 204]:
                        permissions.add("actions:write")
                        permissions.discard("actions:read")
            except Exception as e:
                logger.debug(f"Actions write probe error: {e}")

    def probe_workflow_write(self, repo: str, permissions: set) -> None:
        """Probe whether the token can create workflow files by attempting
        to create a tree entry under .github/workflows/.

        Only called when contents:write is already confirmed.

        Args:
            repo: Repository in org/repo format.
            permissions: Set of detected permissions (mutated in-place).
        """
        if "contents:write" not in permissions:
            return

        try:
            # Get default branch commit
            repo_result = self.api.call_get(f"/repos/{repo}")
            if repo_result.status_code != 200:
                return
            default_branch = repo_result.json()["default_branch"]

            commit_result = self.api.call_get(
                f"/repos/{repo}/commits/{default_branch}"
            )
            if commit_result.status_code != 200:
                return
            commit_sha = commit_result.json()["sha"]

            # Get tree SHA
            tree_result = self.api.call_get(
                f"/repos/{repo}/git/commits/{commit_sha}"
            )
            if tree_result.status_code != 200:
                return
            tree_sha = tree_result.json()["tree"]["sha"]

            # Create a blob for the test file
            blob_result = self.api.call_post(
                f"/repos/{repo}/git/blobs",
                params={"content": "PROBE", "encoding": "utf-8"}
            )
            if blob_result.status_code != 201:
                return
            blob_sha = blob_result.json()["sha"]

            # Create tree with .github/workflows/ entry
            create_tree_result = self.api.call_post(
                f"/repos/{repo}/git/trees",
                params={
                    "tree": [{
                        "path": ".github/workflows/gato_probe",
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_sha,
                    }],
                    "base_tree": tree_sha,
                }
            )
            if create_tree_result.status_code == 201:
                permissions.add("workflows:write")

        except Exception as e:
            logger.debug(f"Workflow write probe error: {e}")

    def run_all_probes(self, repo: str, is_private: bool = True) -> set:
        """Run full probe sequence: read probes, then write probes.

        Args:
            repo: Repository in org/repo format to probe against.
            is_private: Whether the repo is private.

        Returns:
            set: All detected permissions.
        """
        Output.info("Probing endpoints to detect fine-grained permissions...")

        permissions = self.probe_read_permissions(repo, is_private)
        self.probe_write_permissions(repo, permissions)
        self.probe_workflow_write(repo, permissions)

        for perm in sorted(permissions):
            Output.tabbed(f"Detected: {Output.bright(perm)}")

        return permissions
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_probe.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add gato/github/probe.py unit_test/test_probe.py
git commit -m "feat: add PermissionProber for fine-grained PAT discovery"
```

---

### Task 3: Update CLI Token Validation

**Files:**
- Modify: `gato/cli/cli.py:102-128`
- Modify: `unit_test/test_cli.py:47-55`

**Step 1: Update the existing FG PAT rejection test to expect acceptance**

In `unit_test/test_cli.py`, change `test_cli_fine_grained_pat` (line 47):

Replace:
```python
def test_cli_fine_grained_pat(capfd):
    """Test case where an unsupported PAT is provided.
    """
    os.environ["GH_TOKEN"] = "github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "not supported" in err
```

With:
```python
@mock.patch("gato.enumerate.Enumerator.enumerate_organization")
def test_cli_fine_grained_pat(mock_enumerate, capfd):
    """Test case where a fine-grained PAT is accepted.
    """
    os.environ["GH_TOKEN"] = "github_pat_11AAAAAA_" + "A" * 59

    cli.cli(["enumerate", "-t", "test"])
    mock_enumerate.assert_called_once()


def test_cli_fine_grained_pat_malformed(capfd):
    """Test case where a malformed fine-grained PAT is rejected.
    """
    os.environ["GH_TOKEN"] = "github_pat_short"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "malformed" in err
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_cli.py::test_cli_fine_grained_pat -v`
Expected: FAIL — fine-grained PAT still rejected

**Step 3: Update `validate_arguments` in `gato/cli/cli.py`**

Replace lines 102-128 of `gato/cli/cli.py` (the entire `validate_arguments` function):

```python
def validate_arguments(args, parser):
    if "GH_TOKEN" not in os.environ:
        gh_token = input(
            "No 'GH_TOKEN' environment variable set! Please enter a GitHub"
            " PAT.\n"
        )
    else:
        gh_token = os.environ["GH_TOKEN"]

    # Detect token type
    if re.match(r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}$", gh_token):
        token_type = "fine_grained"
    elif ("ghp_" in gh_token or "gho_" in gh_token or "ghu_" in
            gh_token or "ghs_" in gh_token or
            re.match('^[a-fA-F0-9]{40}$', gh_token)):
        token_type = "classic"
    else:
        parser.error(f"{Fore.RED}[!]{Style.RESET_ALL} Provided GitHub PAT is"
                     " malformed!")

    args_dict = vars(args)
    args_dict["gh_token"] = gh_token
    args_dict["token_type"] = token_type

    if args.socks_proxy and args.http_proxy:
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} You cannot use a SOCKS and HTTP"
            " proxy at the same time!"
        )
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_cli.py -v`
Expected: All PASS (including the new FG PAT test)

**Step 5: Commit**

```bash
git add gato/cli/cli.py unit_test/test_cli.py
git commit -m "feat: accept fine-grained PATs in CLI token validation"
```

---

### Task 4: Update Api.check_user() and Add is_fine_grained()

**Files:**
- Modify: `gato/github/api.py:583-666`
- Modify: `unit_test/test_api.py`

**Step 1: Add test for is_fine_grained and FG PAT check_user behavior**

Add to `unit_test/test_api.py`:

```python
def test_is_fine_grained():
    test_pat = "github_pat_11AAAAAA_" + "A" * 59
    api = Api(test_pat, "2022-11-28")
    assert api.is_fine_grained() is True


def test_is_not_fine_grained():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")
    assert api.is_fine_grained() is False


@patch("gato.github.api.requests.get")
def test_check_user_fine_grained_no_scopes_header(mock_get):
    """Fine-grained PATs don't return x-oauth-scopes header."""
    test_pat = "github_pat_11AAAAAA_" + "A" * 59
    api = Api(test_pat, "2022-11-28")

    mock_result = MagicMock()
    mock_result.configure_mock(
        **{
            "headers.get.return_value": None,
            "json.return_value": {'login': 'TestUser', 'name': 'Test User'},
            "status_code": 200
        }
    )
    mock_get.return_value = mock_result

    user_info = api.check_user()

    assert user_info['user'] == 'TestUser'
    assert user_info['scopes'] == []
```

**Step 2: Run tests to verify is_fine_grained fails**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_api.py::test_is_fine_grained -v`
Expected: FAIL — `AttributeError: 'Api' object has no attribute 'is_fine_grained'`

**Step 3: Add `is_fine_grained()` method to Api class**

In `gato/github/api.py`, add after the `is_app_token()` method (line 585):

```python
    def is_fine_grained(self):
        """Returns if the API is using a fine-grained personal access token."""
        return self.pat.startswith("github_pat_")
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/test_api.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add gato/github/api.py unit_test/test_api.py
git commit -m "feat: add is_fine_grained() to Api class"
```

---

### Task 5: Refactor Enumerator to Use TokenCapabilities

**Files:**
- Modify: `gato/enumerate/enumerate.py`
- Modify: `gato/models/organization.py`
- Modify: `unit_test/test_enumerate.py`

This is the largest change. The `Enumerator` class stores `self.user_perms` (a dict with `scopes` list). We add `self.capabilities` (a `TokenCapabilities` instance) and replace all scope string checks.

**Step 1: Update test_enumerate.py for the new capabilities model**

At the top of `unit_test/test_enumerate.py`, add the import:

```python
from gato.models.token import TokenCapabilities
```

Update `test_self_enumerate` (and similar tests) to ensure the `check_user` mock returns data that works with the new flow. The existing test fixtures should continue to work since `Enumerator.__setup_user_info()` will build capabilities from the `check_user()` response.

**Step 2: Modify `Enumerator.__setup_user_info()` in `gato/enumerate/enumerate.py`**

Add import at top:
```python
from gato.models import TokenCapabilities
from gato.github.probe import PermissionProber
```

Replace the `__setup_user_info` method body (lines 71-116). The new version:

```python
    def __setup_user_info(self):
        if not self.user_perms:
            if self.api.is_app_token():
                Output.info("Gato is performing GitHub App enumeration!")

                installed_repos = self.api.get_app_installations()
                if not installed_repos:
                    Output.error("Failed to validate the GitHub App installation token.")
                    return False

                count = installed_repos["total_count"]
                repos_j = installed_repos["repositories"]

                if count <= 0:
                    Output.error("No installed repositories were found!")

                self.user_perms = {
                    "user": "Github App",
                    "scopes": [],
                    "name": "GATO App Mode",
                }
                self.capabilities = TokenCapabilities.for_app_token()

                self.app_installed_repos = [item["owner"]["login"] + "/" + item["name"] for item in repos_j]
            else:
                self.user_perms = self.api.check_user()
                if not self.user_perms:
                    Output.error("This token cannot be used for enumeration!")
                    return False

                Output.info(
                        "The authenticated user is: "
                        f"{Output.bright(self.user_perms['user'])}"
                )

                if self.api.is_fine_grained():
                    # Fine-grained PAT: probe permissions
                    prober = PermissionProber(self.api)
                    repos = prober.discover_accessible_repos()

                    if repos:
                        # Prefer private repo for probing
                        probe_target = repos[0]
                        is_private = probe_target.get("private", False)
                        repo_name = probe_target["full_name"]
                        permissions = prober.run_all_probes(
                            repo_name, is_private
                        )
                    else:
                        permissions = set()
                        Output.warn("No accessible repositories found for"
                                    " permission probing!")

                    self.capabilities = TokenCapabilities.from_fine_grained(
                        user=self.user_perms['user'],
                        name=self.user_perms.get('name', ''),
                        permissions=permissions,
                    )

                    Output.info(
                        f"Token type: {Output.bright('Fine-Grained PAT')}"
                    )
                    Output.info(
                        "Detected permissions: "
                        f"{Output.yellow(self.capabilities.scope_summary())}"
                    )
                else:
                    # Classic PAT: read scopes from header
                    self.capabilities = TokenCapabilities.from_classic_scopes(
                        user=self.user_perms['user'],
                        name=self.user_perms.get('name', ''),
                        scopes=self.user_perms['scopes'],
                    )

                    if len(self.user_perms["scopes"]):
                        Output.info(
                            "The GitHub Classic PAT has the following scopes: "
                            f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                        )
                    else:
                        Output.warn("The token has no scopes!")

                if self.wf_artifacts_enum and not self.capabilities.can_read_contents:
                    Output.error("The token needs read access to retrieve"
                                 " workflow artifacts. Skipping workflow"
                                 " artifact secrets scanning.")
                    self.wf_artifacts_enum = False
        return True
```

Also initialize `self.capabilities = None` in `__init__` (add after `self.user_perms = None` on line 60).

**Step 3: Update `validate_only()` scope check (line 124)**

Replace:
```python
        if 'repo' not in self.user_perms['scopes']:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False
```

With:
```python
        if not self.capabilities.can_read_contents:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False
```

And update the `Organization` constructor call (line 138):

Replace:
```python
        return [Organization({'login': org}, self.user_perms['scopes'], True) for org in orgs]
```
With:
```python
        return [Organization({'login': org}, self.capabilities, True) for org in orgs]
```

**Step 4: Update `self_enumeration()` scope check (line 152)**

Replace:
```python
        if 'repo' not in self.user_perms['scopes']:
            Output.error("Self-enumeration with PAT requires the repo scope!")
            return False
```

With:
```python
        if not self.capabilities.can_read_contents:
            Output.error("Self-enumeration requires content read access!")
            return False
```

**Step 5: Update `enumerate_organization()` (line 214, 222, 258, 267)**

Replace line 214:
```python
        organization = Organization(details, self.user_perms['scopes'])
```
With:
```python
        organization = Organization(details, self.capabilities)
```

Replace line 222:
```python
        Recommender.print_org_findings(
            self.user_perms['scopes'], organization
        )
```
With:
```python
        Recommender.print_org_findings(self.capabilities, organization)
```

Replace lines 257-258:
```python
            Recommender.print_repo_secrets(
                self.user_perms['scopes'],
                repo.secrets
            )
```
With:
```python
            Recommender.print_repo_secrets(self.capabilities, repo.secrets)
```

Replace lines 266-268:
```python
                Recommender.print_repo_attack_recommendations(
                    self.user_perms['scopes'], repo
                )
```
With:
```python
                Recommender.print_repo_attack_recommendations(
                    self.capabilities, repo
                )
```

**Step 6: Update `enumerate_repo_only()` (lines 299, 303-304)**

Replace:
```python
            Recommender.print_repo_secrets(
                self.user_perms['scopes'],
                repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms['scopes'], repo
            )
```
With:
```python
            Recommender.print_repo_secrets(
                self.capabilities, repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.capabilities, repo
            )
```

**Step 7: Update `Organization.__init__()` in `gato/models/organization.py`**

Change the constructor to accept `TokenCapabilities` instead of a scopes list:

Replace lines 10-47:
```python
    def __init__(self, org_data: dict, user_scopes: list, limited_data: bool = False):
        """Wrapper object for an organization.

        Args:
            org_data (dict): Org data from GitHub API
            user_scopes (list): List of OAuth scopes that the PAT has
            limited_data (bool): Whether limited org_data is present (default: False)
        """
```

With:
```python
    def __init__(self, org_data: dict, capabilities, limited_data: bool = False):
        """Wrapper object for an organization.

        Args:
            org_data (dict): Org data from GitHub API
            capabilities: TokenCapabilities instance (or list for backwards compat)
            limited_data (bool): Whether limited org_data is present (default: False)
        """
```

And replace the scope check logic (lines 36-47):
```python
        if "billing_email" in org_data and \
                org_data["billing_email"] is not None:
            if "admin:org" in user_scopes:
                self.org_admin_scopes = True
            self.org_admin_user = True
            self.org_member = True
        elif "billing_email" in org_data:
            self.org_admin_user = False
            self.org_member = True
        else:
            self.org_admin_user = False
            self.org_member = False
```

With:
```python
        # Support both TokenCapabilities and legacy list for backwards compat
        from gato.models.token import TokenCapabilities
        if isinstance(capabilities, TokenCapabilities):
            has_admin_org = capabilities.can_admin_org
        else:
            has_admin_org = "admin:org" in capabilities

        if "billing_email" in org_data and \
                org_data["billing_email"] is not None:
            if has_admin_org:
                self.org_admin_scopes = True
            self.org_admin_user = True
            self.org_member = True
        elif "billing_email" in org_data:
            self.org_admin_user = False
            self.org_member = True
        else:
            self.org_admin_user = False
            self.org_member = False
```

**Step 8: Run all tests**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/ -v`
Expected: All PASS

**Step 9: Commit**

```bash
git add gato/enumerate/enumerate.py gato/models/organization.py unit_test/test_enumerate.py
git commit -m "refactor: enumerator uses TokenCapabilities instead of scope strings"
```

---

### Task 6: Refactor Recommender to Use TokenCapabilities

**Files:**
- Modify: `gato/enumerate/recommender.py`

**Step 1: Update all method signatures and scope checks**

Replace `scopes: list` parameters with `capabilities` and change string checks to boolean checks.

In `print_repo_attack_recommendations` (line 13-14):
```python
    def print_repo_attack_recommendations(
        scopes: list, repository: Repository
    ):
```
→
```python
    def print_repo_attack_recommendations(
        capabilities, repository: Repository
    ):
```

Replace `"workflow" in scopes` (lines 34, 56, 78) with `capabilities.can_write_workflows`.

In `print_repo_secrets` (line 103):
```python
    def print_repo_secrets(scopes, secrets: List[Secret]):
```
→
```python
    def print_repo_secrets(capabilities, secrets: List[Secret]):
```

Replace `'workflow' in scopes` (line 114) with `capabilities.can_write_workflows`.

In `print_org_findings` (line 209):
```python
    def print_org_findings(scopes, organization: Organization):
```
→
```python
    def print_org_findings(capabilities, organization: Organization):
```

Replace `"admin:org" in scopes` (line 218) with `capabilities.can_admin_org`.

**Step 2: Run tests**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/ -v`
Expected: All PASS

**Step 3: Commit**

```bash
git add gato/enumerate/recommender.py
git commit -m "refactor: recommender uses TokenCapabilities"
```

---

### Task 7: Refactor Attacker to Use TokenCapabilities

**Files:**
- Modify: `gato/attack/attack.py`

**Step 1: Update `__setup_user_info` to build capabilities**

Add imports at top of `gato/attack/attack.py`:
```python
from gato.models.token import TokenCapabilities
from gato.github.probe import PermissionProber
```

Replace `__setup_user_info` method (lines 60-83):

```python
    def __setup_user_info(self):
        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                logger.error("This token cannot be used for attacks!")
                return False

            if self.author_email is None:
                self.author_email = \
                    f"{self.user_perms['user']}@users.noreply.github.com"

            if self.author_name is None:
                self.author_name = self.user_perms['name']

            Output.info(
                "The authenticated user is: "
                f"{Output.bright(self.user_perms['user'])}"
            )

            if self.api.is_fine_grained():
                # Fine-grained PAT: probe permissions against target
                prober = PermissionProber(self.api)
                repos = prober.discover_accessible_repos()
                if repos:
                    probe_target = repos[0]
                    is_private = probe_target.get("private", False)
                    permissions = prober.run_all_probes(
                        probe_target["full_name"], is_private
                    )
                else:
                    permissions = set()

                self.capabilities = TokenCapabilities.from_fine_grained(
                    user=self.user_perms['user'],
                    name=self.user_perms.get('name', ''),
                    permissions=permissions,
                )
                Output.info(
                    f"Token type: {Output.bright('Fine-Grained PAT')}"
                )
                Output.info(
                    "Detected permissions: "
                    f"{Output.yellow(self.capabilities.scope_summary())}"
                )
            else:
                self.capabilities = TokenCapabilities.from_classic_scopes(
                    user=self.user_perms['user'],
                    name=self.user_perms.get('name', ''),
                    scopes=self.user_perms['scopes'],
                )
                Output.info(
                    "The GitHub Classic PAT has the following scopes: "
                    f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                )

        return True
```

Add `self.capabilities = None` in `__init__` after `self.user_perms = None`.

**Step 2: Update scope checks in all three attack methods**

In `fork_pr_attack` (lines 290-291), replace:
```python
        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:
```
With:
```python
        if self.capabilities.can_write_contents and \
           self.capabilities.can_write_workflows:
```

In `shell_workflow_attack` (lines 444-445), replace:
```python
        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:
```
With:
```python
        if self.capabilities.can_write_contents and \
           self.capabilities.can_write_workflows:
```

In `secrets_dump` (lines 527-528), replace:
```python
        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:
```
With:
```python
        if self.capabilities.can_write_contents and \
           self.capabilities.can_write_workflows:
```

**Step 3: Run all tests**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/ -v`
Expected: All PASS

**Step 4: Commit**

```bash
git add gato/attack/attack.py
git commit -m "refactor: attacker uses TokenCapabilities for permission gates"
```

---

### Task 8: Final Integration Test and Cleanup

**Files:**
- Verify: All modified files
- Run: Full test suite

**Step 1: Run full test suite**

Run: `cd /Users/carterross/Lab/gato && python -m pytest unit_test/ -v --tb=short`
Expected: All PASS

**Step 2: Verify no remaining raw scope checks**

Run: `cd /Users/carterross/Lab/gato && grep -rn "'repo' in\|'workflow' in\|'admin:org' in\|user_perms\[.scopes.\]" gato/ --include="*.py"`

Expected: No matches in production code (only in test files if any).

**Step 3: Run linting**

Run: `cd /Users/carterross/Lab/gato && python -m flake8 gato/ --max-line-length=120`
Expected: No new errors

**Step 4: Commit any cleanup**

```bash
git add -A
git commit -m "chore: final cleanup for fine-grained PAT support"
```
