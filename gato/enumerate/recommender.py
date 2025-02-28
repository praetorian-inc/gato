from typing import List

from gato.cli import Output
from gato.models import Repository
from gato.models import Organization
from gato.models import Runner
from gato.models import Secret


class Recommender:

    @staticmethod
    def print_repo_attack_recommendations(
        scopes: list, repository: Repository
    ):
        """Prints attack recommendations for repositories.

        Args:
            scopes (list): List of scopes for user who ran Gato.
            repository (Repository): Repository wrapper object.
        """
        if not repository.sh_runner_access:
            if repository.is_admin():
                Output.owned(
                    "The user is an administrator on the repository, but no "
                    "self-hosted runners were detected!"
                )
            return

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
    def print_repo_oidc_info(repository: Repository):
        """Prints information about OIDC connections in repository workflows.

        Args:
            repository (Repository): Repository wrapper object.
        """
        if repository.oidc_enabled and repository.oidc_workflow_names:
            Output.result(
                f"The repository contains {len(repository.oidc_workflow_names)} "
                f"workflow(s) that use OIDC connections for authentication!"
            )
            
            # Group OIDC connections by provider
            providers = {}
            for detail in repository.oidc_details:
                provider = detail.get('provider', 'Unknown')
                if provider not in providers:
                    providers[provider] = []
                providers[provider].append(detail)
            
            # Display OIDC connections grouped by provider
            for provider, details in providers.items():
                Output.tabbed(
                    f"OIDC Provider: {Output.bright(provider)} - "
                    f"Found in {len(details)} job(s)"
                )
                
                for detail in details:
                    workflow_file = detail.get('workflow_file', 'Unknown workflow')
                    job_name = detail.get('job_name', 'Unknown job')
                    
                    if job_name == 'workflow':
                        Output.tabbed(
                            f"  ↳ {Output.bright(workflow_file)}: "
                            f"Workflow-level OIDC permissions"
                        )
                    else:
                        Output.tabbed(
                            f"  ↳ {Output.bright(workflow_file)}: "
                            f"Job '{job_name}'"
                        )
                    
                    # Display assumed role if available
                    if detail.get('assumed_role'):
                        Output.tabbed(
                            f"    ↳ {Output.bright('Assumed Role/Identity')}: {detail['assumed_role']}"
                        )
                    
                    # Display permissions if available
                    if detail.get('permissions'):
                        permissions = detail.get('permissions')
                        Output.tabbed(
                            f"    ↳ Permissions: {', '.join([f'{k}:{v}' for k,v in permissions.items()])}"
                        )
                    
                    # Display specific actions that use OIDC
                    actions = detail.get('actions', [])
                    if actions:
                        for action in actions:
                            action_output = f"    ↳ Action: {Output.bright(action.get('action', 'Unknown'))}"
                            
                            # Add role information to the action if available and different from job-level role
                            if action.get('assumed_role') and action['assumed_role'] != detail.get('assumed_role'):
                                action_output += f" ➡ Role: {action['assumed_role']}"
                                
                            Output.tabbed(action_output)
                            
                            if 'step_name' in action:
                                Output.tabbed(f"      ↳ Step: {action['step_name']}")
            
            # Security implications
            Output.inform(
                "OIDC workflows can potentially obtain credentials for cloud "
                "resources or external services using GitHub identity."
            )
            
            # Common providers and their security implications
            if 'AWS' in providers:
                Output.warn(
                    "AWS OIDC connections can grant access to AWS resources "
                    "based on the IAM role being assumed."
                )
                
                # Check if any AWS connections have roles defined
                aws_roles = set()
                for detail in providers['AWS']:
                    if detail.get('assumed_role'):
                        aws_roles.add(detail['assumed_role'])
                    for action in detail.get('actions', []):
                        if action.get('assumed_role'):
                            aws_roles.add(action['assumed_role'])
                
                if aws_roles:
                    for role in aws_roles:
                        Output.tabbed(f"  ↳ IAM Role: {Output.bright(role)}")
                        
                        # Extract account ID from role ARN if possible
                        if role.startswith('arn:aws:iam::') and ':role/' in role:
                            try:
                                account_id = role.split(':')[4]
                                Output.tabbed(f"    ↳ AWS Account ID: {Output.bright(account_id)}")
                            except:
                                pass
            
            if 'Google Cloud' in providers:
                Output.warn(
                    "Google Cloud OIDC connections can grant access to GCP resources "
                    "based on the service account permissions."
                )
            
            if 'Azure' in providers:
                Output.warn(
                    "Azure OIDC connections can grant access to Azure resources "
                    "based on the assigned roles and permissions."
                )
                
            if 'HashiCorp Vault' in providers:
                Output.warn(
                    "HashiCorp Vault OIDC connections can grant access to secrets "
                    "based on the Vault role's policy."
                )
            
            if repository.can_push():
                Output.owned(
                    "You have push access to this repository and can modify "
                    "workflows with OIDC connections to potentially access "
                    "external resources and assume these roles!"
                )

    @staticmethod
    def print_repo_secrets(scopes, secrets: List[Secret]):
        """Prints list of repository level secrets.

        Args:
            scopes (list): List of OAuth scopes.
            secrets (list[Secret]): List of secret wrapper objects.
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
        """Prints information about repository level self-hosted runners.

        Args:
            repository (Repository): Repository wrapper object.
        """

        if repository.sh_workflow_names:
            Output.result(
                f"The repository contains a workflow: "
                f"{Output.bright(repository.sh_workflow_names[0])} that "
                "might execute on self-hosted runners!"
            )

        if repository.accessible_runners:

            Output.result(
                f"The repository {Output.bright(repository.name)} contains a "
                "previous workflow run that executed on a self-hosted runner!"
            )

            if not type(repository.accessible_runners[0].labels) is list:
                if repository.accessible_runners[0].labels:
                    repository.accessible_runners[0].labels = [repository.accessible_runners[0].labels]
                else:
                    repository.accessible_runners[0].labels = ["Unkown"]

            Output.tabbed(
                "The runner name was: "
                f"{Output.bright(repository.accessible_runners[0].runner_name)}"
                f" and the machine name was "
                f"{Output.bright(repository.accessible_runners[0].machine_name)}"
                f" and the runner type was "
                f"{Output.bright(repository.accessible_runners[0].runner_type)}"
                f" in the {Output.bright(repository.accessible_runners[0].runner_group)} group"
                f" with the following labels: "
                f"{Output.bright(', '.join(repository.accessible_runners[0].labels))}"
            )

            for runner in repository.accessible_runners:
                if runner.non_ephemeral:
                    Output.owned("The repository contains a non-ephemeral self-hosted runner!")
                    break

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
        """Prints findings related to an organization, and provides context for
        attacks/future investigation based on the scopes a user has.

        Args:
            organization (Organization): Organization wrapper object.
        """
        if organization.org_admin_user:
            Output.owned("The user is an organization owner!")
            if "admin:org" in scopes:
                Output.result(
                    f"The token also has the {Output.yellow('admin:org')} "
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
            Recommender.print_runner_info(organization.runners)

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
