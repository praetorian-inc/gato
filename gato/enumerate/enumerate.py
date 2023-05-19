import logging
import os


from gato.github import Api
from gato.git import Git
from gato.workflow_parser import WorkflowParser
from gato.models import Repository
from gato.cli import Output

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
        skip_clones: bool = False,
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
            github_url=github_url,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_clones = skip_clones
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.user_perms = None
        self.github_url = github_url

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

    def __print_attack_recommendations(self, repository: Repository):
        """Prints attack recommendations for the repository.
        Args:
            repository (Repository): Wrapped repository object.
        """
        if repository.is_admin():
            Output.owned(
                "The user is an administrator on the repository!"
            )
            if "workflow" in self.user_perms["scopes"]:
                Output.result(
                    "The PAT also has the workflow scope, which means a "
                    "custom YAML payload can be used!"
                )
            else:
                Output.inform(
                    "The PAT does not have the workflow scope, which means an "
                    "existing workflow trigger must be used!"
                )
                Output.tabbed(
                    "Look for a job in the workflow YAML that checks out the "
                    "repository, AND then runs code that can be modified "
                    "within the repository!"
                )
                if repository.is_public():
                    Output.tabbed(
                        "Additionally, since the repository is public this "
                        "token can be used to approve a malicious fork PR!"
                    )
        elif repository.is_maintainer():
            Output.result("The user is a maintainer on the repository!")
            if "workflow" in self.user_perms["scopes"]:
                Output.result(
                    "The user also has the workflow scope, which means a "
                    "custom YAML payload can be used!"
                )
            else:
                Output.inform(
                    "The user does not have the workflow scope, which means "
                    "an existing workflow trigger must be used!"
                )
                Output.tabbed(
                    "Look for a job in the workflow YAML that checks out the "
                    "repository, AND then runs code that can be modified "
                    "within the repository!"
                )
                if repository.is_public():
                    Output.tabbed(
                        "Additionally, since the repository is public this "
                        "token can be used to approve a malicious fork PR!"
                    )
        elif repository.can_push():
            Output.result("The user can push to the repository!")
            if "workflow" in self.user_perms["scopes"]:
                Output.owned(
                    "The user also has the workflow scope, which means a "
                    "custom YAML payload can be used!"
                )
            else:
                Output.inform(
                    "The user does not have the workflow scope, which means "
                    "an existing workflow trigger must be used!"
                )
                Output.tabbed(
                    "Look for a job in the workflow YAML that checks out the "
                    "repository, AND then runs code that can be modified "
                    "within the repository!"
                )

        elif repository.can_pull():
            if repository.can_fork():
                Output.inform(
                    "The user can only pull from the repository, but forking "
                    "is allowed! Only a fork pull-request based attack would "
                    "be possible."
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

            Output.tabbed(
                f"Name: {Output.bright(runner_name)}, OS: "
                f"{Output.bright(runner_os)} Status: "
                f"{Output.bright(runner_status)}"
            )
            Output.tabbed(
                f"The runner has the following labels: {labels}!"
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
                    Output.result(
                        f"The repository contains a workflow:"
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
            github_url=self.github_url.split('/')[2] if self.github_url else None
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
                    Output.result(
                        f"The repository contains a workflow: "
                        f"{Output.bright(wf)} that executes on self-hosted"
                        f" runners!"
                    )

                    if self.output_yaml:
                        success = parsed_yml.output(self.output_yaml)
                        if not success:
                            logger.warning("Failed to write yml to disk!")
                        else:
                            path = os.path.join(
                                self.output_yaml, f'{repository.name}/{wf}'
                            )
                            Output.result(f"{wf} saved to {path}")

            # At this point we only know the extension, so handle and
            #  ignore malformed yml files.
            except Exception as parse_error:
                Output.error(parse_error)
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
            Output.result(
                    f"The repository {repository.name} contains a previous "
                    "workflow run that executed on a self-hosted runner!"
            )
            Output.tabbed(
                "The runner name was: "
                f"{Output.bright(wf_runs[0]['runner_name'])} "
                f"and the machine name was "
                f"{Output.bright(wf_runs[0]['machine_name'])}"
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

        Output.result(f"Enumerating the {Output.bright(org)} organization!")

        # If fields such as billing email are populated, then the user MUST
        # be an organization owner. If not, then the user is a member (for
        # private repos) or
        if "billing_email" in details and details["billing_email"] is not None:
            Output.owned("The user is an organization owner!")

            if "admin:org" in self.user_perms["scopes"]:
                Output.result(
                    f"The token also has the {Output.yellow('org:admin')} "
                    "scope. This token has extensive access to the GitHub"
                    " organization!"
                )
            org_admin_user = True
            check_org_private = True
        elif "billing_email" in details:
            Output.result("The user is likely an organization member!")
            org_admin_user = False
            check_org_private = True
        else:
            org_admin_user = False
            check_org_private = False
            Output.warn("The user has only public access!")
        if org_admin_user and 'admin:org' in self.user_perms:
            runners = self.api.check_org_runners(org)
            if runners:
                Output.result(
                    f"The organization has {len(runners['runners'])} org-level"
                    " self-hosted runners!"
                )
                self.__print_runner_info(runners)

            org_secrets = self.api.get_org_secrets(org)

            if org_secrets:
                Output.owned(
                    f"The organization has {Output.bright(len(org_secrets))}"
                    " secret(s)!")
                Output.result("The secret names are:")
                for secret in org_secrets:
                    Output.tabbed(
                        f"\t{Output.bright(secret['name'])}, "
                        f"last updated {secret['updated_at']}"
                    )

        if check_org_private:
            org_private_repos = self.__assemble_repo_list(
                org, ['private', 'internal']
            )
        else:
            org_private_repos = []

        org_public_repos = self.__assemble_repo_list(org, ['public'])

        Output.info(
            f"About to enumerate "
            f"{len(org_private_repos) + len(org_public_repos)} repos within "
            f"the {org} organization!"
        )

        if org_private_repos or org_public_repos:
            all_repos = org_private_repos+org_public_repos
            sso_enabled = self.api.validate_sso(org, all_repos[0].name)

            if sso_enabled:
                if org_private_repos:
                    Output.header(
                        f"Enumerating private repos in {Output.bright(org)}"
                    )
                    for repo in org_private_repos:
                        self.enumerate_repository(repo,
                                                  clone=not self.skip_clones)
                        self.enumerate_repository_secrets(
                            repo, org_secrets=False
                        )
                if org_public_repos:
                    Output.header(
                        f"Enumerating public repos in {Output.bright(org)}"
                    )
                    for repo in org_public_repos:
                        self.enumerate_repository(
                            repo, clone=not self.skip_clones
                        )
                        self.enumerate_repository_secrets(
                            repo, org_secrets=False
                        )
            else:
                Output.error("SSO is not enabled for this Org!")
                if org_private_repos:
                    Output.result(
                        f"Due to Enterprise Access, this PAT can list the "
                        f"private repos in {Output.bright(org)}:"
                    )
                    for i in org_private_repos:
                        Output.result(
                            f"- {Output.bright(i.name)}"
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
            self.enumerate_repository_secrets(repo, org_secrets=True)
        else:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not "
                " exist or the user does not have access."
            )

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
            Output.error("The list of repositories was empty!")
            return

        for repo in repo_names:
            self.enumerate_repo_only(repo, clone)

    def enumerate_repository_secrets(
            self, repository: Repository, org_secrets: bool = False):
        """Enumerate secrets accessible to a repository.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
            org_secrets (bool): Whether print all org secrets accessible.
        """
        if repository.can_push():
            secrets = self.api.get_secrets(repository.name)

            if org_secrets:
                org_secrets = self.api.get_repo_org_secrets(repository.name)
                secrets.extend(org_secrets)

            if secrets:
                if 'workflow' in self.user_perms['scopes']:
                    Output.owned(
                        "The repository can access "
                        f"{Output.bright(len(secrets))} secrets and the "
                        "token can use a workflow to read them!")

                    Output.result("The secret names are:")
                    for secret in secrets:
                        Output.tabbed(f"\t{Output.bright(secret['name'])}, "
                                      f"last updated {secret['updated_at']}")

                else:
                    Output.info(
                        f"The repository can access "
                        f"{Output.bright(len(secrets))} secrets, but the "
                        "token cannot trigger a new workflow!")
                    for secret in secrets:
                        Output.tabbed(f"\t{Output.bright(secret['name'])},"
                                      f" last updated {secret['updated_at']}")

    def enumerate_repository(self, repository: Repository, clone: bool = True):
        """Enumerate a repository, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
            clone (bool, optional):  Whether to use repo contents API
            in order to analayze the yaml files. Defaults to True.
        """

        if not self.__setup_user_info():
            return False

        Output.tabbed(
            f"Enumerating: {Output.bright(repository.name)}!"
        )
        runner_detected = False

        if not repository.can_pull():
            Output.error("The user cannot push or pull, skipping.")
            return

        if repository.is_admin():
            runners = self.api.get_repo_runners(repository.name)
            if runners:
                runner_detected = True
                Output.result(
                    f"The repository has {len(runners)} repo-level "
                    "self-hosted runners!"
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
