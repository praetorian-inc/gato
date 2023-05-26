import logging
import json

from gato.github import Api
from gato.models import Repository, Organization
from gato.cli import Output
from gato.enumerate.repository import RepositoryEnum
from gato.enumerate.organization import OrganizationEnum
from gato.enumerate.recommender import Recommender

logger = logging.getLogger(__name__)


class Enumerator:
    """Class holding all high level logic for enumerating GitHub, whether it is
    a user's entire access, individual organizations, or repositories.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        output_yaml: str = None,
        skip_log: bool = False,
        github_url: str = None
    ):
        """Initialize enumeration class with arguments sent by user.

        Args:
            pat (str): GitHub personal access token
            socks_proxy (str, optional): Proxy settings for SOCKS proxy.
            Defaults to None.
            http_proxy (str, optional): Proxy gettings for HTTP proxy.
            Defaults to None.
            output_yaml (str, optional): If set, directory to save all yml
            files to . Defaults to None.
            skip_log (bool, optional): If set, then run logs will not be
            downloaded.
        """
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.user_perms = None
        self.github_url = github_url

        self.repo_e = RepositoryEnum(self.api, skip_log, output_yaml)
        self.org_e = OrganizationEnum(self.api)

    def __setup_user_info(self):
        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                logger.error("This token cannot be used for enumeration!")
                return False

            Output.info(
                    "The authenticated user is: "
                    f"{Output.bright(self.user_perms['user'])}"
            )
            if len(self.user_perms["scopes"]):
                Output.info(
                    "The GitHub Classic PAT has the following scopes: "
                    f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                )
            else:
                Output.warn("The token has no scopes!")

        return True

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.

        Returns:
            bool: False if the PAT is not valid for enumeration.
        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.error("Self-enumeration requires the repo scope!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        for org in orgs:
            self.enumerate_organization(org)

    def enumerate_organization(self, org: str):
        """Enumerate an entire organization, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            org (str): Organization to perform enumeration on.

        Returns:
            bool: False if a failure occurred enumerating the organization.
        """

        if not self.__setup_user_info():
            return False

        details = self.api.get_organization_details(org)

        if not details:
            Output.warn(
                f"Unable to query the org: {Output.bright(org)}! Ensure the "
                "organization exists!")
            return False

        organization = Organization(details, self.user_perms['scopes'])

        Output.result(f"Enumerating the {Output.bright(org)} organization!")

        if organization.org_admin_user and organization.org_admin_scopes:
            self.org_e.admin_enum(organization)

        Recommender.print_org_findings(
            self.user_perms['scopes'], organization
        )

        enum_list = self.org_e.construct_repo_enum_list(organization)

        Output.info(
            f"About to enumerate "
            f"{len(organization.private_repos) + len(organization.public_repos)}"
            " repos within "
            f"the {organization.name} organization!"
        )

        for repo in enum_list:

            Output.tabbed(
                f"Enumerating: {Output.bright(repo.name)}!"
            )
            self.repo_e.enumerate_repository(repo)
            self.repo_e.enumerate_repository_secrets(repo)

            Recommender.print_repo_secrets(
                self.user_perms['scopes'],
                repo.secrets
            )
            Recommender.print_repo_runner_info(repo)

            # Only print info about individual repos if user is admin OR
            # we detect a runner.
            if repo.is_admin() or repo.sh_runner_access:
                Recommender.print_repo_attack_recommendations(
                    self.user_perms['scopes'], repo
                )

    def enumerate_repo_only(self, repo_name: str):
        """Enumerate only a single repository. No checks for org-level
        self-hosted runners will be performed in this case.

        Args:
            repo_name (str): Repository name in {Org/Owner}/Repo format.
            clone (bool, optional): Whether to clone the repo
            in order to analayze the yaml files. Defaults to True.
        """
        if not self.__setup_user_info():
            return False

        repo_data = self.api.get_repository(repo_name)
        if repo_data:
            repo = Repository(repo_data)

            Output.tabbed(
                f"Enumerating: {Output.bright(repo.name)}!"
            )
            self.repo_e.enumerate_repository(repo)
            self.repo_e.enumerate_repository_secrets(repo)
            Recommender.print_repo_secrets(
                self.user_perms['scopes'],
                repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms['scopes'], repo
            )
        else:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not "
                " exist or the user does not have access."
            )

    def enumerate_repos(self, repo_names: list):
        """Enumerate a list of repositories, each repo must be in Org/Repo name
        format.

        Args:
            repo_names (list): Repository name in {Org/Owner}/Repo format.
        """
        if not self.__setup_user_info():
            return False

        if len(repo_names) == 0:
            Output.error("The list of repositories was empty!")
            return

        for repo in repo_names:
            self.enumerate_repo_only(repo)
