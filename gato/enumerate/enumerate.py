import logging

from gato.github import Api
from gato.github import GqlQueries
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
        github_url: str = None,
        output_json: str = None,
        no_sleep: bool = False,
        wf_artifacts_enum: str = False,
        skip_sh_runner_enum: str = False,
        include_all_artifact_secrets: bool = False,
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
            output_json (str, optional): JSON file to output enumeration
            results.
        """
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
            no_sleep=no_sleep,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.user_perms = None
        self.github_url = github_url
        self.output_json = output_json
        self.wf_artifacts_enum = wf_artifacts_enum
        self.skip_sh_runner_enum = skip_sh_runner_enum
        self.include_all_artifact_secrets = include_all_artifact_secrets
        self.repo_e = RepositoryEnum(self.api, skip_log, output_yaml,
                                     skip_sh_runner_enum)
        self.org_e = OrganizationEnum(self.api)
        self.app_installed_repos = None

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
                if len(self.user_perms["scopes"]):
                    Output.info(
                        "The GitHub Classic PAT has the following scopes: "
                        f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                    )
                else:
                    Output.warn("The token has no scopes!")

                if self.wf_artifacts_enum and "repo" not in self.user_perms["scopes"]:
                    Output.error("The token needs repo scope to retrieve workflow artifacts. "
                                 "Skipping workflow artifact secrets scanning.")
                    self.wf_artifacts_enum = False
        return True

    def validate_only(self):
        """Validates the PAT access and exits.
        """
        if not self.__setup_user_info():
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        return [Organization({'login': org}, self.user_perms['scopes'], True) for org in orgs]

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user,
        as well as personal/collaborator repositories.

        Returns:
            list: List of Organization wrapper objects.
        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.error("Self-enumeration with PAT requires the repo scope!")
            return False

        # Get organizations the user belongs to
        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        org_wrappers = []
        for org in orgs:
            org_wrapper = self.enumerate_organization(org)
            if org_wrapper:
                org_wrappers.append(org_wrapper)

        # Add enumeration of personal and collaborator repositories
        Output.info("Enumerating personal and collaborator repositories...")
        
        # Get repositories the user has access to 
        user_repos = self.api.get_user_repositories()
        
        if user_repos:
            Output.info(f"Found {len(user_repos)} personal/collaborator repositories")
            
            # We want to analyze all repositories thoroughly, don't treat this as a large enum
            # since personal repositories are typically fewer and more important
            large_enum = len(user_repos) > 100
            
            for repo_data in user_repos:
                repo = Repository(repo_data)
                Output.tabbed(f"Enumerating: {Output.bright(repo.name)}!")
                
                # Pass large_org_enum parameter as False to ensure we analyze run logs
                self.repo_e.enumerate_repository(repo, large_org_enum=large_enum)
                self.repo_e.enumerate_repository_secrets(repo)
                
                if self.wf_artifacts_enum:
                    self.repo_e.enumerate_workflow_artifacts(repo, self.include_all_artifact_secrets)
                    
                Recommender.print_repo_secrets(
                    self.user_perms['scopes'],
                    repo.secrets + repo.org_secrets
                )
                Recommender.print_repo_runner_info(repo)
                Recommender.print_repo_attack_recommendations(
                    self.user_perms['scopes'], repo
                )
        else:
            Output.info("No personal or collaborator repositories found")

        return org_wrappers

    def app_enumeration(self):
        """Enumerates availabe repositories associated with the authenticated GitHub app.

        Returns:
            bool: False if the token is not valid for enumeration.
        """
        if not self.__setup_user_info():
            return False

        Output.info(
            f'The GitHub App Installation token has access to {len(self.app_installed_repos)} '
            'repositories! Note that Gato does not determine GitHub App '
            'Installation token access level and will only perform read-level '
            'analysis.')

        Output.info("Accessible Repositories:")
        for repo in self.app_installed_repos:
            Output.tabbed(f"{Output.bright(repo)}")

        Output.info("Enumerating each repository")
        return self.enumerate_repos(self.app_installed_repos)

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

        if not self.skip_sh_runner_enum:
            Output.info("Querying and caching workflow YAML files!")
            wf_queries = GqlQueries.get_workflow_ymls(enum_list)
            for wf_query in wf_queries:
                result = self.org_e.api.call_post('/graphql', wf_query)
                # Sometimes we don't get a 200, fall back in this case.
                if result.status_code == 200:
                    self.repo_e.construct_workflow_cache(result.json()['data']['nodes'])
                else:
                    Output.warn("GraphQL query failed, will revert to REST workflow query for impacted repositories!")

        for repo in enum_list:
            Output.tabbed(
                f"Enumerating: {Output.bright(repo.name)}!"
            )

            self.repo_e.enumerate_repository(repo, large_org_enum=len(enum_list) > 100)
            self.repo_e.enumerate_repository_secrets(repo)

            if self.wf_artifacts_enum:
                self.repo_e.enumerate_workflow_artifacts(repo, self.include_all_artifact_secrets)

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

        return organization

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

            if self.wf_artifacts_enum:
                self.repo_e.enumerate_workflow_artifacts(repo, self.include_all_artifact_secrets)

            Recommender.print_repo_secrets(
                self.user_perms['scopes'],
                repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms['scopes'], repo
            )

            return repo
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

        repo_wrappers = []
        for repo in repo_names:
            repo_obj = self.enumerate_repo_only(repo)
            if repo_obj:
                repo_wrappers.append(repo_obj)

        return repo_wrappers
