from typing import List

from gato.cli import Output
from gato.models import Repository
from gato.models import Organization
from gato.models import Runner
from gato.models import Secret


class Recommender:

    @staticmethod
    def print_repo_attack_recommendations(scopes, repository: Repository):
        """_summary_

        Args:
            scopes (_type_): _description_
            repository (_type_): _description_
        """
        if repository.is_admin():
            Output.owned(
                "The user is an administrator on the repository!"
            )
            if "workflow" in scopes:
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
            if "workflow" in scopes:
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
            if "workflow" in scopes:
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

    @staticmethod
    def print_repo_secrets(scopes, secrets: list[Secret]):
        """_summary_

        Args:
            scopes (_type_): _description_
            secrets (list[Secret]): _description_
        """

        if not secrets:
            return

        if 'workflow' in scopes:
            Output.owned(
                "The repository can access "
                f"{Output.bright(len(secrets))} secrets and the "
                "token can use a workflow to read them!")
        else:
            Output.info(
                f"The repository can access "
                f"{Output.bright(len(secrets))} secrets, but the "
                "token cannot trigger a new workflow!")

        for secret in secrets:
            Output.tabbed(
                f"\t{Output.bright(secret.name)},"
                f" last updated {secret.secret_data['updated_at']}"
            )

    @staticmethod
    def print_repo_runner_info(repository: Repository):

        if repository.accessible_runners:

            Output.result(
                f"The repository {repository.name} contains a previous "
                "workflow run that executed on a self-hosted runner!"
            )

            Output.tabbed(
                "The runner name was: "
                f"{Output.bright(repository.accessible_runners[0].runner_name)}"
                f" and the machine name was "
                f"{Output.bright(repository.accessible_runners[0].machine_name)}"
            )

        if repository.runners:
            Output.result(
                f"The repository has {len(repository.runners)} repo-level"
                " self-hosted runners!"
            )
            Recommender.print_runner_info(repository.runners)

    @staticmethod
    def print_runner_info(runners: List[Runner]):
        """Print information about runners.

        Args:
            runners (dict): Runner result returned from the GitHub API
        """

        for runner in runners:
            runner_name = runner.runner_name
            runner_os = runner.os
            runner_status = runner.status
            labels = ', '.join([elem['name'] for elem in runner.labels])

            Output.tabbed(
                f"Name: {Output.bright(runner_name)}, OS: "
                f"{Output.bright(runner_os)} Status: "
                f"{Output.bright(runner_status)}"
            )

            if labels:
                Output.tabbed(
                    f"The runner has the following labels: {labels}!"
                )

    @staticmethod
    def print_org_findings(scopes, organization: Organization):
        """_summary_

        Args:
            organization (Organization): _description_
        """
        if organization.org_admin_user:
            Output.owned("The user is an organization owner!")
            if "admin:org" in scopes:
                Output.result(
                    f"The token also has the {Output.yellow('org:admin')} "
                    "scope. This token has extensive access to the GitHub"
                    " organization!"
                )
        elif organization.org_member:
            Output.result("The user is likely an organization member!")
        else:
            Output.warn("The user has only public access!")

        if organization.runners:
            Output.result(
                f"The organization has {len(organization.runners)} org-level"
                " self-hosted runners!"
            )

        if organization.secrets:
            Output.owned(
                f"The organization has "
                f"{Output.bright(len(organization.secrets))} secret(s)!")
            Output.result("The secret names are:")
            for secret in organization.secrets:
                Output.tabbed(
                    f"\t{Output.bright(secret.name)}, "
                    f"last updated {secret.secret_data['updated_at']}"
                )
