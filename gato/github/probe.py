import logging

from gato.cli import Output

logger = logging.getLogger(__name__)


class PermissionProber:
    """Discovers fine-grained PAT permissions by probing API endpoints.

    Probes are designed to be no-ops — they don't create visible artifacts.
    Read probes use GET requests. Write probes use minimal POST/PUT that
    produce only dangling/unreferenced objects.
    """

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
        self.api = api

    def discover_accessible_repos(self) -> list:
        """Discover repositories accessible to the fine-grained PAT.

        Returns private repos first (better for probing).
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
        """Probe GET endpoints to detect read permissions."""
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
        """Probe write access. Mutates permissions set in-place."""
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
        """Probe workflow write by creating a tree under .github/workflows/."""
        if "contents:write" not in permissions:
            return

        try:
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

            tree_result = self.api.call_get(
                f"/repos/{repo}/git/commits/{commit_sha}"
            )
            if tree_result.status_code != 200:
                return
            tree_sha = tree_result.json()["tree"]["sha"]

            blob_result = self.api.call_post(
                f"/repos/{repo}/git/blobs",
                params={"content": "PROBE", "encoding": "utf-8"}
            )
            if blob_result.status_code != 201:
                return
            blob_sha = blob_result.json()["sha"]

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
        """Run full probe sequence: read probes, then write probes."""
        Output.info("Probing endpoints to detect fine-grained permissions...")

        permissions = self.probe_read_permissions(repo, is_private)
        self.probe_write_permissions(repo, permissions)
        self.probe_workflow_write(repo, permissions)

        for perm in sorted(permissions):
            Output.tabbed(f"Detected: {Output.bright(perm)}")

        return permissions
