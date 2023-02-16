import logging

from colorama import Fore, Style

from gato.github import Api
from gato.git import Git
from gato.workflow_parser import WorkflowParser
from gato.models import Repository
from gato.cli import (
    GREEN_PLUS,
    GREEN_EXCLAIM,
    YELLOW_EXCLAIM,
    RED_DASH,
    BRIGHT_DASH,
    bright,
)

logger = logging.getLogger(__name__)
logging.root.setLevel(logging.DEBUG)


class Enumerator:
    """Class holding all high level logic for enumerating GitHub, whether it is
    a user's entire access, individual organizations, or repositories.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        skip_clones: bool = False,
        output_yaml: str = None,
        skip_log: bool = False,
    ):
        """Initialize enumeration class with arguments sent by user.

        Args:
            pat (str): GitHub personal access token
            socks_proxy (str, optional): Proxy settings for SOCKS proxy.
            Defaults to None.
            http_proxy (str, optional): Proxy gettings for HTTP proxy.
            Defaults to None.
            skip_clones (bool, optional): Whether to skip git clone operations
            (which will prevent scanning workflow yml files).
            Defaults to False.
            output_yaml (str, optional): If set, directory to save all yml
            files.
            to (if clones are not skipped). Defaults to None.
            skip_log (bool, optional): If set, then run logs will not be
            downloaded.
        """
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_clones = skip_clones
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.user_perms = None

    def __setup_user_info(self):
        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                logger.error("This token cannot be used for enumeration!")
                return False

            print(
                f"{GREEN_PLUS} The authenticated user is:"
                f' {Style.BRIGHT}{self.user_perms["user"]}{Style.RESET_ALL}'
            )
            if len(self.user_perms["scopes"]):
                print(
                    f"{GREEN_PLUS} The GitHub Classic PAT has the following"
                    " scopes:"
                    f' {Fore.YELLOW}{", ".join(self.user_perms["scopes"])}'
                    f"{Style.RESET_ALL}!"
                )
            else:
                print(
                    f"{YELLOW_EXCLAIM} The token has no scopes!"
                )

        return True

    def __print_attack_recommendations(self, repository: Repository):
        """Prints attack recommendations for the repository.
        Args:
            repository (Repository): Wrapped repository object.
        """
        if repository.is_admin():
            print(
                f"{GREEN_EXCLAIM} The user is an administrator on the"
                " repository!"
            )
            if "workflow" in self.user_perms["scopes"]:
                print(
                    f"{GREEN_EXCLAIM} The user also has the workflow"
                    " scope, which means a custom YAML payload can be"
                    " used!"
                )
            else:
                print(
                    f"{YELLOW_EXCLAIM} The user does not have the workflow"
                    " scope, which means an existing workflow trigger must"
                    " be used!"
                )
                print(
                    f"{BRIGHT_DASH} Look for a job in the workflow YAML"
                    " that checks out the repository, AND then runs code"
                    " that can be modified within the repository!"
                )
                if repository.is_public():
                    print(
                        f"{BRIGHT_DASH} Additionally, since the repository"
                        " is public this token can be used to approve a"
                        " malicious fork PR!"
                    )
        elif repository.is_maintainer():
            print(
                f"{GREEN_EXCLAIM} The user is a maintainer on the"
                " repository!"
            )
            if "workflow" in self.user_perms["scopes"]:
                print(
                    f"{GREEN_EXCLAIM} The user also has the workflow"
                    " scope, which means a custom YAML payload can be"
                    " used!"
                )
            else:
                print(
                    f"{YELLOW_EXCLAIM} The user does not have the workflow"
                    " scope, which means an existing workflow trigger must"
                    " be used!"
                )
                print(
                    f"{BRIGHT_DASH} Look for a job in the workflow YAML"
                    " that checks out the repository, AND then runs code"
                    " that can be modified within the repository!"
                )
                if repository.is_public():
                    print(
                        f"{BRIGHT_DASH} Additionally, since the repository"
                        " is public this token can be used to approve a"
                        " malicious fork PR!"
                    )
        elif repository.can_push():
            print(f"{GREEN_PLUS} The user can push to the repository!")
            if "workflow" in self.user_perms["scopes"]:
                print(
                    f"{GREEN_EXCLAIM} The user also has the workflow"
                    " scope, which means a custom YAML payload can be"
                    " used!"
                )
            else:
                print(
                    f"{YELLOW_EXCLAIM} The user does not have the workflow"
                    " scope, which means an existing workflow trigger must"
                    " be used!"
                )
                print(
                    f"{BRIGHT_DASH} Look for a job in the workflow YAML"
                    " that checks out the repository, AND then runs code"
                    " that can be modified within the repository!"
                )

        elif repository.can_pull():
            if repository.can_fork():
                print(
                    f"{YELLOW_EXCLAIM} The user can only pull from the"
                    " repository, but forking is allowed! Only a fork"
                    " pull-request based attack would be possible."
                )

    def __print_runner_info(self, runners: dict):
        """Print information about runners.

        Args:
            runners (dict): Runner result returned from the GitHub API
        """

        for runner in runners['runners']:
            runner_name = runner['name']
            runner_os = runner['os']
            runner_status = runner['status']
            labels = ', '.join([elem['name'] for elem in runner['labels']])

            print(
                f"{BRIGHT_DASH} Name: {bright(runner_name)},"
                f" OS: {bright(runner_os)} Status: {bright(runner_status)}"
            )
            print(
                f"{ BRIGHT_DASH} The runner has the following labels: "
                f"{Fore.YELLOW}{labels}{Style.RESET_ALL}!"
            )

    def __perform_yml_enumeration(self, repository: Repository):
        """Enumerates the repository using the API to extract yml files. This
        does not generate any git clone audit log events.

        Args:
            repository (Repository): Wrapped repository object.
        """
        runner_detected = False
        ymls = self.api.retrieve_workflow_ymls(repository.name)

        for (wf, yml) in ymls:
            try:
                parsed_yml = WorkflowParser(yml, repository.name, wf)

                self_hosted_jobs = parsed_yml.self_hosted()

                if self_hosted_jobs:
                    runner_detected = True
                    print(
                        f"{GREEN_PLUS} The repository contains a workflow:"
                        f" {wf} that executes on self-hosted runners!"
                    )

                    if self.output_yaml:
                        success = parsed_yml.output(self.output_yaml)
                        if not success:
                            logger.warning("Failed to write yml to disk!")

            # At this point we only know the extension, so handle and
            #  ignore malformed yml files.
            except Exception as parse_error:
                print(parse_error)
                logger.warning("Attmpted to parse invalid yaml!")

        return runner_detected

    def __perform_clone_enumeration(self, repository: Repository):
        """Performs enumeration on the repository after cloning it.

        Args:
            repository (Repository): Wrapped repository object.

        Returns:
            bool: True if a self-hosted runner was detected.
        """
        runner_detected = False

        cloned_repo = Git(
            self.api.pat,
            repository.name,
            proxies=self.api.proxies,
        )

        status = cloned_repo.perform_clone()
        if not status:
            return False

        ymls = cloned_repo.extract_workflow_ymls()

        for (wf, yml) in ymls:
            try:
                parsed_yml = WorkflowParser(yml, repository.name, wf)

                self_hosted_jobs = parsed_yml.self_hosted()

                if self_hosted_jobs:
                    runner_detected = True
                    print(
                        f"{GREEN_PLUS} The repository contains a workflow:"
                        f" {wf} that executes on self-hosted runners!"
                    )

                    if self.output_yaml:
                        success = parsed_yml.output(self.output_yaml)
                        if not success:
                            logger.warning("Failed to write yml to disk!")

            # At this point we only know the extension, so handle and
            #  ignore malformed yml files.
            except Exception as parse_error:
                print(parse_error)
                logger.warning("Attmpted to parse invalid yaml!")

        return runner_detected

    def __perform_runlog_enumeration(self, repository: Repository):
        """Enumerate for the presence of a self-hosted runner based on
        downloading historical runlogs.

        Args:
            repository (Repository): Wrapped repository object.

        Returns:
            bool: True if a self-hosted runner was detected.
        """

        runner_detected = False
        wf_runs = self.api.retrieve_run_logs(
                repository.name, short_circuit=True
            )

        if wf_runs:
            print(
                f"{GREEN_PLUS} The repository {repository.name} contains a"
                " previous workflow run that executed on a self-hosted"
                " runner!"
            )
            print(
                f"{BRIGHT_DASH} The runner name was:"
                f" {bright(wf_runs[0]['runner_name'])}"
                " and the machine name was"
                f" {bright(wf_runs[0]['machine_name'])}"
            )
            logger.info(
                f"The repository {repository.name} contains a previous"
                " workflow run that executed on a self-hosted runner!"
            )
            runner_detected = True

        return runner_detected

    def __assemble_repo_list(self, organization: str, visibilities: list):
        """Get a list of repositories that match the visibility types.

        Args:
            organization (str): Name of the organization.
            visibilities (list): List of visibilities (public, private, etc)
        """

        repos = []
        for visibility in visibilities:
            raw_repos = self.api.check_org_repos(organization, visibility)
            if raw_repos:
                repos.extend([Repository(repo) for repo in raw_repos])

        return repos

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.

        Returns:
            bool: False if the PAT is not valid for enumeration.
        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' not in self.user_perms['scopes']:
            print(f"{RED_DASH} Self-enumeration requires the repo scope!")
            return False

        orgs = self.api.check_organizations()

        print(
            f'{GREEN_PLUS} The user { self.user_perms["user"] } belongs to'
            f" {len(orgs)} organizations!"
        )

        for org in orgs:
            print(f"    {BRIGHT_DASH} {org}")

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
            print(f"{YELLOW_EXCLAIM} Unable to query the org: {bright(org)}!"
                  f" Ensure the organization exists!")
            return False

        print(f"{BRIGHT_DASH} Enumerating the {bright(org)} organization!")

        # If fields such as billing email are populated, then the user MUST
        # be an organization owner. If not, then the user is a member (for
        # private repos) or
        if "billing_email" in details and details["billing_email"] is not None:
            print(f"{GREEN_PLUS} The user is an organization owner!")

            if "admin:org" in self.user_perms["scopes"]:
                print(
                    f"{GREEN_EXCLAIM} The token also has the"
                    f" {Fore.YELLOW}org:admin{Style.RESET_ALL} scope. This"
                    " token has extensive access to the GitHub organization!"
                )
            org_admin_user = True
            check_org_private = True
        elif "billing_email" in details:
            print(f"{GREEN_PLUS} The user is likely an organization member!")
            org_admin_user = False
            check_org_private = True
        else:
            org_admin_user = False
            check_org_private = False
            print(f"{YELLOW_EXCLAIM} The user has only public access!")
        if org_admin_user:
            runners = self.api.check_org_runners(org)
            if runners:
                print(
                    f"{GREEN_PLUS} The organization has "
                    f"{len(runners['runners'])} org-level self-hosted runners!"
                )
                self.__print_runner_info(runners)

        if check_org_private:
            org_private_repos = self.__assemble_repo_list(
                org, ['private', 'internal']
            )
        else:
            org_private_repos = []

        org_public_repos = self.__assemble_repo_list(org, ['public'])

        print(
            f"{GREEN_PLUS} About to enumerate"
            f" {len(org_private_repos) + len(org_public_repos)} repos within"
            f" the {org} organization!"
        )

        if org_private_repos or org_public_repos:
            all_repos = org_private_repos+org_public_repos
            sso_enabled = self.api.validate_sso(org, all_repos[0].name)

            if sso_enabled:

                if org_private_repos:
                    print(
                        f"{bright('---')} Enumerating private repos in"
                        f" {Style.BRIGHT}{org}{Style.RESET_ALL}"
                        f" {bright('---')}"
                    )
                    for repo in org_private_repos:
                        self.enumerate_repository(repo,
                                                  clone=not self.skip_clones)
                if org_public_repos:
                    print(
                        f" {bright('---')}Enumerating public repos in"
                        f" {bright(org)} {bright('---')} "
                    )
                    for repo in org_public_repos:
                        self.enumerate_repository(
                            repo, clone=not self.skip_clones
                        )
            else:
                print(
                    f"{RED_DASH} SSO is not enabled for this Org!"
                )
                if org_private_repos:
                    print(
                        f"Due to Enterprise Access, this PAT can list the"
                        f" private repos in {org}:"
                    )
                    for i in org_private_repos:
                        print(
                            f"- {Style.BRIGHT}{i.name}{Style.RESET_ALL}"
                        )

    def enumerate_repo_only(self, repo_name: str, clone: bool = True):
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

            self.enumerate_repository(repo, clone=not self.skip_clones)
        else:
            print(f"{YELLOW_EXCLAIM} Unable to enumerate "
                  f"{bright(repo_name)}! It may not exist or the user does not"
                  f" have access.")

    def enumerate_repos(self, repo_names: list, clone: bool = True):
        """Enumerate a list of repositories, each repo must be in Org/Repo name
        format.

        Args:
            repo_names (list): Repository name in {Org/Owner}/Repo format.
            clone (bool, optional):  Whether to clone the repo
            in order to analayze the yaml files. Defaults to True.
        """
        if not self.__setup_user_info():
            return False

        if len(repo_names) == 0:
            print(f"{RED_DASH} The list of repositories was empty!")
            return

        for repo in repo_names:
            self.enumerate_repo_only(repo, clone)

    def enumerate_repository(self, repository: Repository, clone: bool = True):
        """Enumerate an entire organization, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
            clone (bool, optional):  Whether to use repo contents API
            in order to analayze the yaml files. Defaults to True.
        """

        if not self.__setup_user_info():
            return False

        print(
            f"{BRIGHT_DASH} Enumerating:"
            f" {Style.BRIGHT}{repository.name}{Style.RESET_ALL}!"
        )
        runner_detected = False

        if not repository.can_pull():
            print(f"{RED_DASH} The user cannot push or pull, skipping.")
            return

        if repository.is_admin():
            runners = self.api.get_repo_runners(repository.name)
            if runners:
                runner_detected = True
                print(
                    f"{GREEN_PLUS} The repository has "
                    f"{len(runners)} repo-level self-hosted runners!"
                )
                self.__print_runner_info({"runners": runners})

        if not self.skip_log and self.__perform_runlog_enumeration(repository):
            runner_detected = True

        # For now still respecting the skip clone flag until we have clarity
        # regarding logging impact.
        if clone and self.__perform_yml_enumeration(repository):
            runner_detected = True

        if runner_detected:
            # Only display permissions (beyond having none) if runner is
            # detected.
            self.__print_attack_recommendations(repository)
